// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
//! Background delivery of push notifications.
//!
//! Delivering a push notification is a network call to a URL the client
//! chose, so it can take as long as the sender's timeout. Doing it inline in
//! the execution loop would let one slow webhook delay the task's events for
//! every subscriber. The [`PushDispatcher`] moves delivery off that path:
//!
//! * Each task id has its own bounded FIFO queue and at most one delivery
//!   worker, so events for one task are delivered in the order they were
//!   produced, and a slow webhook only delays later pushes for that task.
//! * Enqueueing never waits. When a task's queue already holds
//!   [`PUSH_QUEUE_CAPACITY_PER_TASK`] events a non-terminal event is dropped,
//!   a warning is logged, and, when the sender is strict (`fail_on_error`),
//!   the drop is reported to the event's error sink. Terminal events are
//!   always kept, so a webhook that was merely slow still learns how the task
//!   ended; the real bound on a queue is therefore the capacity plus one
//!   terminal event per execution or cancellation.
//! * A task delivers to at most [`MAX_CONCURRENT_PUSH_DELIVERIES_PER_TASK`]
//!   of its webhooks at once.
//! * At most [`MAX_CONCURRENT_PUSH_DELIVERIES`] webhook requests are in flight
//!   at once across all tasks. That pool is shared, so with many busy tasks it
//!   still bounds the total throughput by design. A request holds a slot only
//!   while it is in flight, never while a delivery waits to retry, and a
//!   single task can never hold more than its per-task share, so a slow task
//!   cannot delay another task's pushes by more than the time of one request.
//! * The worker for a task is removed in the same critical section that finds
//!   its queue empty, so a later event for the task starts a new worker and
//!   two workers for one task never overlap. A panic inside a delivery is
//!   caught, reported, and does not stop the worker.
//! * The configs of a task are read when a job is delivered, not when it is
//!   enqueued: a config created after an event was queued can still receive
//!   it, and one deleted before delivery will not.
//!
//! Events still queued when the process exits are not delivered; push
//! delivery is best effort, as the protocol leaves delivery guarantees to the
//! server.

use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use a2a::{A2AError, StreamResponse};
use futures::{FutureExt, StreamExt};
use tokio::sync::{Semaphore, oneshot};

use super::{HttpPushSender, PushConfigStore};

/// Largest number of events held for one task while its webhook is slow.
///
/// Further non-terminal events are dropped (with a warning) rather than
/// letting the execution wait or the queue grow without bound. Terminal
/// events are never dropped, so a queue can hold this many plus one terminal
/// event per execution or cancellation.
pub(crate) const PUSH_QUEUE_CAPACITY_PER_TASK: usize = 64;

/// Default number of one task's webhooks that are delivered to concurrently.
pub(crate) const MAX_CONCURRENT_PUSH_DELIVERIES_PER_TASK: usize = 4;

/// Default number of webhook requests in flight at one time, across all
/// tasks of one handler.
pub(crate) const MAX_CONCURRENT_PUSH_DELIVERIES: usize = 32;

/// Called with the first delivery error of an event.
pub(crate) type PushErrorSink = Arc<dyn Fn(A2AError) + Send + Sync>;

/// Receives the outcome of one job: the first delivery error, if any.
pub(crate) type PushDone = oneshot::Sender<Result<(), A2AError>>;

/// The error reported when a task's queue drops an event under a strict sender.
fn queue_full_error() -> A2AError {
    A2AError::internal("push notification queue full: an event was not delivered")
}

/// The error reported when the worker that held a job failed before it could
/// report the outcome.
pub(crate) fn worker_lost_error() -> A2AError {
    A2AError::internal("push notification delivery worker failed")
}

/// One event waiting to be delivered, with everything needed to deliver it.
pub(crate) struct PushJob {
    /// The event to deliver to every config registered for the task. `None`
    /// is a barrier: it delivers nothing and only completes `done` once every
    /// earlier job of the task has been delivered.
    pub(crate) event: Option<StreamResponse>,
    /// A terminal event is never dropped for lack of queue space.
    pub(crate) terminal: bool,
    /// Where configs are read from, at delivery time.
    pub(crate) store: Arc<dyn PushConfigStore>,
    /// The sender used for delivery.
    pub(crate) sender: Arc<HttpPushSender>,
    /// Notified of the first failure for this event, if anyone cares. Not
    /// called when `done` is set: the outcome goes to `done` instead.
    pub(crate) on_error: Option<PushErrorSink>,
    /// Receives the outcome of this job, for a caller that waits for it.
    pub(crate) done: Option<PushDone>,
}

/// Per-task background push delivery. See the module documentation.
pub(crate) struct PushDispatcher {
    /// A key is present exactly while a worker for that task id is running.
    queues: Mutex<HashMap<String, VecDeque<PushJob>>>,
    permits: Arc<Semaphore>,
    per_task: usize,
}

impl PushDispatcher {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_limits(
            MAX_CONCURRENT_PUSH_DELIVERIES_PER_TASK,
            MAX_CONCURRENT_PUSH_DELIVERIES,
        )
    }

    /// A dispatcher delivering to at most `per_task` webhooks of one task and
    /// at most `global` requests across all tasks at once (both at least 1).
    pub(crate) fn with_limits(per_task: usize, global: usize) -> Arc<Self> {
        Arc::new(PushDispatcher {
            queues: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(global.max(1))),
            per_task: per_task.max(1),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, VecDeque<PushJob>>> {
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue `job` for `task_id` without waiting. Must be called inside a
    /// Tokio runtime, because it may start the task's delivery worker.
    pub(crate) fn enqueue(self: &Arc<Self>, task_id: &str, job: PushJob) {
        let mut queues = self.lock();
        match queues.get_mut(task_id) {
            Some(queue) => {
                if queue.len() >= PUSH_QUEUE_CAPACITY_PER_TASK && !job.terminal {
                    drop(queues);
                    tracing::warn!(
                        task_id,
                        capacity = PUSH_QUEUE_CAPACITY_PER_TASK,
                        "push queue full, dropping event"
                    );
                    if job.sender.fail_on_error() {
                        report(job.on_error.as_ref(), job.done, queue_full_error());
                    }
                    return;
                }
                queue.push_back(job);
            }
            None => {
                queues.insert(task_id.to_owned(), VecDeque::from([job]));
                drop(queues);
                let dispatcher = Arc::clone(self);
                let task_id = task_id.to_owned();
                tokio::spawn(async move { dispatcher.run_worker(task_id).await });
            }
        }
    }

    async fn run_worker(self: Arc<Self>, task_id: String) {
        loop {
            let job = {
                let mut queues = self.lock();
                match queues.get_mut(&task_id).and_then(VecDeque::pop_front) {
                    Some(job) => job,
                    None => {
                        queues.remove(&task_id);
                        return;
                    }
                }
            };
            let on_error = job.on_error.clone();
            let has_done = job.done.is_some();
            // A panic in a user's store or in the sender must not leave the
            // task's queue without a worker, or later events would pile up
            // behind a worker that no longer exists.
            if AssertUnwindSafe(self.deliver(&task_id, job))
                .catch_unwind()
                .await
                .is_err()
            {
                tracing::error!(task_id = %task_id, "push delivery panicked; the worker continues");
                // A job with `done` reports through the dropped sender, which
                // its receiver sees as `worker_lost_error`.
                if !has_done {
                    report(on_error.as_ref(), None, worker_lost_error());
                }
            }
        }
    }

    async fn deliver(&self, task_id: &str, job: PushJob) {
        let PushJob {
            event,
            store,
            sender,
            on_error,
            done,
            ..
        } = job;
        let outcome = match event {
            Some(event) => self.deliver_event(task_id, event, store, sender).await,
            None => None,
        };
        match (done, outcome) {
            (Some(done), outcome) => {
                let _ = done.send(outcome.map_or(Ok(()), Err));
            }
            (None, Some(error)) => report(on_error.as_ref(), None, error),
            (None, None) => {}
        }
    }

    /// Deliver `event` to every config of the task; returns the first error.
    async fn deliver_event(
        &self,
        task_id: &str,
        event: StreamResponse,
        store: Arc<dyn PushConfigStore>,
        sender: Arc<HttpPushSender>,
    ) -> Option<A2AError> {
        let configs = match store.list(task_id).await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!(task_id, %error, "listing push configs failed");
                return Some(error);
            }
        };

        // Every config gets the event before the next event is taken from
        // the queue, so each webhook sees the task's events in order. The
        // task delivers to `per_task` configs at a time; the shared permit is
        // taken by the sender around each request only.
        let results = futures::stream::iter(configs)
            .map(|config| {
                let sender = Arc::clone(&sender);
                let permits = Arc::clone(&self.permits);
                let event = event.clone();
                async move { sender.send_push_gated(&config, event, Some(&permits)).await }
            })
            .buffer_unordered(self.per_task)
            .collect::<Vec<_>>()
            .await;

        let mut first = None;
        for error in results.into_iter().filter_map(Result::err) {
            tracing::error!(task_id, %error, "push delivery failed");
            first.get_or_insert(error);
        }
        first
    }
}

/// Send `error` to whoever waits for the job: its `done` receiver if it has
/// one, else its error sink.
fn report(on_error: Option<&PushErrorSink>, done: Option<PushDone>, error: A2AError) {
    if let Some(done) = done {
        let _ = done.send(Err(error));
    } else if let Some(on_error) = on_error {
        on_error(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryPushConfigStore;
    use a2a::{Task, TaskPushNotificationConfig, TaskState, TaskStatus};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn working_task() -> StreamResponse {
        StreamResponse::Task(Task {
            id: "t".into(),
            context_id: "c".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
    }

    fn job(store: Arc<dyn PushConfigStore>) -> PushJob {
        PushJob {
            event: Some(working_task()),
            terminal: false,
            store,
            sender: Arc::new(HttpPushSender::new(None)),
            on_error: None,
            done: None,
        }
    }

    /// A store whose `list` blocks until released, so queues can be filled.
    struct GatedStore {
        release: tokio::sync::Notify,
        lists: AtomicUsize,
    }

    #[async_trait]
    impl PushConfigStore for GatedStore {
        async fn save(
            &self,
            config: TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Ok(config)
        }
        async fn get(&self, _t: &str, c: &str) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::task_not_found(c))
        }
        async fn list(&self, _t: &str) -> Result<Vec<TaskPushNotificationConfig>, A2AError> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Ok(Vec::new())
        }
        async fn delete(&self, _t: &str, _c: &str) -> Result<(), A2AError> {
            Ok(())
        }
        async fn delete_all(&self, _t: &str) -> Result<(), A2AError> {
            Ok(())
        }
    }

    /// A store whose first `list` panics.
    struct PanicOnceStore {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl PushConfigStore for PanicOnceStore {
        async fn save(
            &self,
            config: TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Ok(config)
        }
        async fn get(&self, _t: &str, c: &str) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::task_not_found(c))
        }
        async fn list(&self, _t: &str) -> Result<Vec<TaskPushNotificationConfig>, A2AError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("test store panics once");
            }
            Ok(Vec::new())
        }
        async fn delete(&self, _t: &str, _c: &str) -> Result<(), A2AError> {
            Ok(())
        }
        async fn delete_all(&self, _t: &str) -> Result<(), A2AError> {
            Ok(())
        }
    }

    /// Wait until `done` reports the job, or fail after a generous bound.
    async fn outcome(receiver: oneshot::Receiver<Result<(), A2AError>>) -> Result<(), A2AError> {
        tokio::time::timeout(Duration::from_secs(10), receiver)
            .await
            .expect("the job was never completed")
            .unwrap_or_else(|_| Err(worker_lost_error()))
    }

    #[tokio::test]
    async fn workers_are_torn_down_per_task() {
        let dispatcher = PushDispatcher::new();
        let store: Arc<dyn PushConfigStore> = Arc::new(InMemoryPushConfigStore::new());
        let mut last = None;
        for i in 0..500 {
            for n in 0..3 {
                let mut j = job(Arc::clone(&store));
                if n == 2 {
                    let (tx, rx) = oneshot::channel();
                    j.done = Some(tx);
                    last = Some(rx);
                }
                dispatcher.enqueue(&format!("task-{i}"), j);
            }
            // Wait for each task's last job so its worker has emptied the queue.
            if let Some(rx) = last.take() {
                outcome(rx).await.unwrap();
            }
        }
        // The worker removes its key under the lock when it finds the queue
        // empty; give the last workers a moment to run that final pop.
        for _ in 0..200 {
            if dispatcher.lock().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            dispatcher.lock().is_empty(),
            "leaked {} task queues",
            dispatcher.lock().len()
        );
    }

    #[tokio::test]
    async fn a_panicking_delivery_does_not_wedge_the_task() {
        let dispatcher = PushDispatcher::new();
        let store = Arc::new(PanicOnceStore {
            calls: AtomicUsize::new(0),
        });
        let dyn_store: Arc<dyn PushConfigStore> = store.clone();

        let errors = Arc::new(AtomicUsize::new(0));
        let mut first = job(Arc::clone(&dyn_store));
        let counter = Arc::clone(&errors);
        first.on_error = Some(Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        dispatcher.enqueue("t", first);

        // The second event goes to the same task id. Its delivery completing
        // proves the worker survived the panic.
        let (tx, rx) = oneshot::channel();
        let mut second = job(Arc::clone(&dyn_store));
        second.done = Some(tx);
        dispatcher.enqueue("t", second);
        outcome(rx).await.unwrap();

        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(errors.load(Ordering::SeqCst), 1, "the panic was reported");
    }

    #[tokio::test]
    async fn a_job_whose_delivery_panics_reports_a_named_error() {
        let dispatcher = PushDispatcher::new();
        let store: Arc<dyn PushConfigStore> = Arc::new(PanicOnceStore {
            calls: AtomicUsize::new(0),
        });
        let (tx, rx) = oneshot::channel();
        let mut j = job(store);
        j.done = Some(tx);
        dispatcher.enqueue("t", j);
        let error = outcome(rx).await.unwrap_err();
        assert!(error.message.contains("worker failed"), "{error:?}");
    }

    #[tokio::test]
    async fn a_full_queue_drops_non_terminal_events_and_keeps_terminal_ones() {
        let dispatcher = PushDispatcher::new();
        let store = Arc::new(GatedStore {
            release: tokio::sync::Notify::new(),
            lists: AtomicUsize::new(0),
        });
        let dyn_store: Arc<dyn PushConfigStore> = store.clone();
        let sender = Arc::new(HttpPushSender::new(Some(crate::HttpPushSenderConfig {
            fail_on_error: true,
            ..Default::default()
        })));
        let dropped = Arc::new(AtomicUsize::new(0));

        let make = |terminal: bool, done: Option<PushDone>| {
            let counter = Arc::clone(&dropped);
            PushJob {
                event: Some(working_task()),
                terminal,
                store: Arc::clone(&dyn_store),
                sender: Arc::clone(&sender),
                on_error: Some(Arc::new(move |error: A2AError| {
                    if error.message.contains("queue full") {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                })),
                done,
            }
        };

        // The first job is taken by the worker and blocks in `list`; the
        // next PUSH_QUEUE_CAPACITY_PER_TASK fill the queue.
        dispatcher.enqueue("t", make(false, None));
        while store.lists.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        for _ in 0..PUSH_QUEUE_CAPACITY_PER_TASK {
            dispatcher.enqueue("t", make(false, None));
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 0);

        // One more non-terminal event is dropped and reported.
        dispatcher.enqueue("t", make(false, None));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);

        // A terminal event is kept even though the queue is at capacity.
        let (tx, rx) = oneshot::channel();
        dispatcher.enqueue("t", make(true, Some(tx)));
        assert_eq!(
            dispatcher.lock().get("t").map(VecDeque::len),
            Some(PUSH_QUEUE_CAPACITY_PER_TASK + 1)
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);

        // Release everything; the terminal job's outcome arrives last.
        let release = Arc::clone(&store);
        let pump = tokio::spawn(async move {
            loop {
                release.release.notify_one();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        outcome(rx).await.unwrap();
        pump.abort();
    }
}
