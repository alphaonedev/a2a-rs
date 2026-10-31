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
//!   [`PUSH_QUEUE_CAPACITY_PER_TASK`] events the event is dropped and a
//!   warning is logged; terminal events are always kept, so a webhook that
//!   was merely slow still learns how the task ended.
//! * At most [`MAX_CONCURRENT_PUSH_DELIVERIES`] webhook requests are in flight
//!   at once across all tasks.
//! * The worker for a task is removed in the same critical section that finds
//!   its queue empty, so a later event for the task starts a new worker and
//!   two workers for one task never overlap.
//!
//! Events still queued when the process exits are not delivered; push
//! delivery is best effort, as the protocol leaves delivery guarantees to the
//! server.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use a2a::{A2AError, StreamResponse};
use futures::StreamExt;
use tokio::sync::Semaphore;

use super::{HttpPushSender, PushConfigStore};

/// Largest number of events held for one task while its webhook is slow.
///
/// Further non-terminal events are dropped (with a warning) rather than
/// letting the execution wait or the queue grow without bound.
pub(crate) const PUSH_QUEUE_CAPACITY_PER_TASK: usize = 64;

/// Largest number of webhook requests in flight at one time, across all
/// tasks of one handler. Also bounds how many of one task's configs are
/// delivered to concurrently.
pub(crate) const MAX_CONCURRENT_PUSH_DELIVERIES: usize = 32;

/// Called with the first delivery error of an event.
pub(crate) type PushErrorSink = Arc<dyn Fn(A2AError) + Send + Sync>;

/// One event waiting to be delivered, with everything needed to deliver it.
pub(crate) struct PushJob {
    /// The event to deliver to every config registered for the task.
    pub(crate) event: StreamResponse,
    /// A terminal event is never dropped for lack of queue space.
    pub(crate) terminal: bool,
    /// Where configs are read from, at delivery time.
    pub(crate) store: Arc<dyn PushConfigStore>,
    /// The sender used for delivery.
    pub(crate) sender: Arc<HttpPushSender>,
    /// Notified of the first failure for this event, if anyone cares.
    pub(crate) on_error: Option<PushErrorSink>,
}

/// Per-task background push delivery. See the module documentation.
pub(crate) struct PushDispatcher {
    /// A key is present exactly while a worker for that task id is running.
    queues: Mutex<HashMap<String, VecDeque<PushJob>>>,
    permits: Arc<Semaphore>,
}

impl PushDispatcher {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(PushDispatcher {
            queues: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_PUSH_DELIVERIES)),
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
                    tracing::warn!(
                        task_id,
                        capacity = PUSH_QUEUE_CAPACITY_PER_TASK,
                        "push queue full, dropping event"
                    );
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
            self.deliver(&task_id, job).await;
        }
    }

    async fn deliver(&self, task_id: &str, job: PushJob) {
        let PushJob {
            event,
            store,
            sender,
            on_error,
            ..
        } = job;
        let configs = match store.list(task_id).await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!(task_id, %error, "listing push configs failed");
                if let Some(on_error) = &on_error {
                    on_error(error);
                }
                return;
            }
        };

        // Every config gets the event before the next event is taken from
        // the queue, so each webhook sees the task's events in order.
        let results = futures::stream::iter(configs)
            .map(|config| {
                let sender = Arc::clone(&sender);
                let permits = Arc::clone(&self.permits);
                let event = event.clone();
                async move {
                    // The semaphore is never closed.
                    let _permit = permits.acquire_owned().await.ok();
                    sender.send_push(&config, event).await
                }
            })
            .buffer_unordered(MAX_CONCURRENT_PUSH_DELIVERIES)
            .collect::<Vec<_>>()
            .await;

        let mut reported = false;
        for error in results.into_iter().filter_map(Result::err) {
            tracing::error!(task_id, %error, "push delivery failed");
            if !reported {
                reported = true;
                if let Some(on_error) = &on_error {
                    on_error(error);
                }
            }
        }
    }
}
