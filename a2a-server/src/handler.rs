// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
use a2a::*;
use async_trait::async_trait;
use futures::{StreamExt, stream::BoxStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{RwLock, broadcast, oneshot};

use crate::push::dispatcher::{PushDispatcher, PushErrorSink, PushJob};

use crate::middleware::ServiceParams;
use crate::pagination::resolve_page_size;
use crate::task_store::apply_history_length;

const EXECUTION_BUFFER_CAPACITY: usize = 32;

#[derive(Clone)]
struct ExecutionEvent {
    sequence: u64,
    result: Result<StreamResponse, A2AError>,
}

#[derive(Default)]
struct ActiveExecutionState {
    sequence: u64,
    snapshot_task: Option<Task>,
}

struct ActiveExecution {
    sender: broadcast::Sender<ExecutionEvent>,
    state: RwLock<ActiveExecutionState>,
    /// First push delivery error reported by the background dispatcher, kept
    /// until the execution loop picks it up (see `drive_execution`).
    push_failure: std::sync::Mutex<Option<A2AError>>,
    /// Woken by the first recorded push failure, so a strict execution that
    /// is waiting for deliveries returns at once (see `await_push_or_failure`).
    push_failed: tokio::sync::Notify,
    /// Set once a push failure is recorded: the dispatcher then skips every
    /// job of this execution that is still queued.
    push_abandoned: Arc<AtomicBool>,
}

impl ActiveExecution {
    fn new(task: Task) -> Arc<Self> {
        let (sender, _) = broadcast::channel(EXECUTION_BUFFER_CAPACITY);
        Arc::new(Self {
            sender,
            state: RwLock::new(ActiveExecutionState {
                sequence: 0,
                snapshot_task: Some(task),
            }),
            push_failure: std::sync::Mutex::new(None),
            push_failed: tokio::sync::Notify::new(),
            push_abandoned: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Remember a push delivery error; only the first one is kept.
    fn record_push_failure(&self, error: A2AError) {
        let mut slot = self
            .push_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.get_or_insert(error);
        drop(slot);
        self.push_abandoned.store(true, Ordering::SeqCst);
        self.push_failed.notify_one();
    }

    fn take_push_failure(&self) -> Option<A2AError> {
        self.push_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn subscribe(&self) -> broadcast::Receiver<ExecutionEvent> {
        self.sender.subscribe()
    }

    async fn resubscribe(&self) -> (broadcast::Receiver<ExecutionEvent>, Option<Task>, u64) {
        let receiver = self.sender.subscribe();
        let state = self.state.read().await;
        (receiver, state.snapshot_task.clone(), state.sequence)
    }

    async fn publish(
        &self,
        result: Result<&StreamResponse, &A2AError>,
        snapshot_task: Option<Task>,
    ) {
        let sequence = {
            let mut state = self.state.write().await;
            if let Some(task) = snapshot_task {
                state.snapshot_task = Some(task);
            }
            state.sequence += 1;
            state.sequence
        };

        // Task state remains available for a later subscription, but transient
        // events do not need to be allocated when no subscriber is listening.
        if self.sender.receiver_count() == 0 {
            return;
        }

        let event = ExecutionEvent {
            sequence,
            result: result.cloned().map_err(Clone::clone),
        };
        let _ = self.sender.send(event);
    }

    async fn snapshot_is_terminal(&self) -> bool {
        let state = self.state.read().await;
        state
            .snapshot_task
            .as_ref()
            .is_some_and(|task| task.status.state.is_terminal())
    }
}

#[derive(Default)]
struct ExecutionManager {
    executions: RwLock<HashMap<TaskId, Arc<ActiveExecution>>>,
}

impl ExecutionManager {
    async fn start(&self, task: Task) -> Result<Arc<ActiveExecution>, A2AError> {
        let mut executions = self.executions.write().await;
        if executions.contains_key(&task.id) {
            return Err(A2AError::invalid_request(format!(
                "task execution is already in progress: {}",
                task.id
            )));
        }

        let active = ActiveExecution::new(task.clone());
        executions.insert(task.id.clone(), active.clone());
        Ok(active)
    }

    async fn get(&self, task_id: &str) -> Option<Arc<ActiveExecution>> {
        let executions = self.executions.read().await;
        executions.get(task_id).cloned()
    }

    async fn resubscribe(
        &self,
        task_id: &str,
    ) -> Option<(broadcast::Receiver<ExecutionEvent>, Option<Task>, u64)> {
        let active = self.get(task_id).await?;
        let (receiver, snapshot_task, sequence) = active.resubscribe().await;
        Some((receiver, snapshot_task, sequence))
    }

    async fn finish(&self, task_id: &str, active: &Arc<ActiveExecution>) {
        let mut executions = self.executions.write().await;
        let should_remove = executions
            .get(task_id)
            .is_some_and(|current| Arc::ptr_eq(current, active));
        if should_remove {
            executions.remove(task_id);
        }
    }
}

struct ExecutionRuntime {
    executor: Arc<dyn crate::AgentExecutor>,
    task_store: Arc<dyn crate::TaskStore>,
    push_config_store: Option<Arc<dyn crate::PushConfigStore>>,
    push_sender: Option<Arc<crate::HttpPushSender>>,
    push_dispatcher: Arc<PushDispatcher>,
    execution_manager: Arc<ExecutionManager>,
}

struct SubscriptionState {
    receiver: broadcast::Receiver<ExecutionEvent>,
    snapshot_task: Option<Task>,
    min_sequence: u64,
    done: bool,
}

fn is_terminal_event(event: &StreamResponse) -> bool {
    match event {
        StreamResponse::Task(task) => task.status.state.is_terminal(),
        StreamResponse::StatusUpdate(update) => update.status.state.is_terminal(),
        _ => false,
    }
}

fn task_id_for_event(event: &StreamResponse) -> Option<&str> {
    match event {
        StreamResponse::Task(task) => Some(&task.id),
        StreamResponse::StatusUpdate(update) => Some(&update.task_id),
        StreamResponse::ArtifactUpdate(update) => Some(&update.task_id),
        StreamResponse::Message(_) => None,
    }
}

fn should_interrupt_non_streaming(
    req: &SendMessageRequest,
    event: &StreamResponse,
) -> Option<TaskId> {
    if req
        .configuration
        .as_ref()
        .and_then(|config| config.return_immediately)
        .unwrap_or(false)
    {
        return match event {
            StreamResponse::Message(_) => None,
            _ => task_id_for_event(event).map(ToOwned::to_owned),
        };
    }

    match event {
        StreamResponse::Task(task) if task.status.state == TaskState::AuthRequired => {
            Some(task.id.clone())
        }
        StreamResponse::StatusUpdate(update) if update.status.state == TaskState::AuthRequired => {
            Some(update.task_id.clone())
        }
        _ => None,
    }
}

/// Receives the outcome of one queued push job.
type PushOutcome = oneshot::Receiver<Result<(), A2AError>>;

/// Hand `event` (or, for `None`, a barrier that completes once the task's
/// earlier pushes are delivered) to the background push dispatcher.
///
/// Never waits for delivery: the event is queued behind the earlier events of
/// the same task and delivered by that task's worker. Does nothing when push
/// notifications are not configured. A delivery failure is logged by the
/// dispatcher and reported to `on_error`. With `wait` the outcome is returned
/// instead, for a caller that waits for it (see [`await_push`]).
#[allow(clippy::too_many_arguments)]
fn enqueue_push(
    dispatcher: &Arc<PushDispatcher>,
    task_id: &str,
    push_config_store: Option<&Arc<dyn crate::PushConfigStore>>,
    push_sender: Option<&Arc<crate::HttpPushSender>>,
    event: Option<&StreamResponse>,
    on_error: Option<PushErrorSink>,
    abandon: Option<Arc<AtomicBool>>,
    wait: bool,
) -> Option<PushOutcome> {
    let (Some(store), Some(sender)) = (push_config_store, push_sender) else {
        return None;
    };
    let (done, outcome) = if wait {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    dispatcher.enqueue(
        task_id,
        PushJob {
            event: event.cloned(),
            terminal: event.is_none_or(is_terminal_event),
            store: Arc::clone(store),
            sender: Arc::clone(sender),
            on_error,
            abandon,
            done,
        },
    );
    outcome
}

/// Checks that need no request, run before an event is queued so that they
/// fail the event synchronously in both modes, as they did when delivery was
/// inline: the config store must be readable and every config of the task
/// must pass the sender's URL and header checks. Only the outcome of the
/// requests themselves is gated by `fail_on_error`.
async fn precheck_push(
    push_config_store: Option<&Arc<dyn crate::PushConfigStore>>,
    push_sender: Option<&Arc<crate::HttpPushSender>>,
    task_id: &str,
) -> Result<(), A2AError> {
    let (Some(store), Some(sender)) = (push_config_store, push_sender) else {
        return Ok(());
    };
    for config in store.list(task_id).await? {
        sender.precheck(&config)?;
    }
    Ok(())
}

/// The first delivery error of a job enqueued with `wait`.
async fn await_push(outcome: PushOutcome) -> Result<(), A2AError> {
    outcome
        .await
        .unwrap_or_else(|_| Err(crate::push::dispatcher::worker_lost_error()))
}

/// [`await_push`], but returning at the first push failure recorded for the
/// execution: nothing queued after a known failure is waited for.
async fn await_push_or_failure(
    active: &ActiveExecution,
    outcome: PushOutcome,
) -> Result<(), A2AError> {
    tokio::select! {
        result = await_push(outcome) => result,
        () = active.push_failed.notified() => Err(active
            .take_push_failure()
            .unwrap_or_else(crate::push::dispatcher::worker_lost_error)),
    }
}

/// Whether delivery failures must reach the caller (`fail_on_error`).
fn push_is_strict(
    push_config_store: Option<&Arc<dyn crate::PushConfigStore>>,
    push_sender: Option<&Arc<crate::HttpPushSender>>,
) -> bool {
    push_config_store.is_some() && push_sender.is_some_and(|sender| sender.fail_on_error())
}

async fn save_task(task_store: &dyn crate::TaskStore, mut task: Task) -> Result<Task, A2AError> {
    // DM-SERIAL-001: a persisted/returned task status must carry a timestamp.
    // This is the single persistence chokepoint for executor events, so
    // backfilling here covers the task-snapshot and status-update paths
    // alike, while preserving any timestamp the executor already supplied.
    if task.status.timestamp.is_none() {
        task.status.timestamp = Some(chrono::Utc::now());
    }
    match task_store.update(task.clone()).await {
        Ok(_) => Ok(task),
        Err(error) if error.code == error_code::TASK_NOT_FOUND => {
            task_store.create(task.clone()).await?;
            Ok(task)
        }
        Err(error) => Err(error),
    }
}

/// DM-SERIAL-001: backfills a missing status timestamp on the event itself,
/// before it is both persisted (via `apply_event_to_task`/`save_task`) and
/// broadcast to any live subscriber -- `save_task`'s own backfill only
/// covers what gets persisted; a subscriber watching `send_streaming_message`
/// or `subscribe_to_task` receives the broadcast event directly, never a
/// reload from the store, so backfilling only at persistence time still
/// leaves a live subscriber seeing a timestamp-less status.
fn backfill_status_timestamp(event: &mut StreamResponse) {
    let status = match event {
        StreamResponse::Task(task) => &mut task.status,
        StreamResponse::StatusUpdate(update) => &mut update.status,
        StreamResponse::ArtifactUpdate(_) | StreamResponse::Message(_) => return,
    };
    if status.timestamp.is_none() {
        status.timestamp = Some(chrono::Utc::now());
    }
}

async fn apply_event_to_task(
    task_store: &dyn crate::TaskStore,
    current_task: Option<Task>,
    event: &StreamResponse,
) -> Result<Option<Task>, A2AError> {
    match event {
        StreamResponse::Task(task) => save_task(task_store, task.clone()).await.map(Some),
        StreamResponse::StatusUpdate(update) => {
            let mut task = match current_task {
                Some(task) => task,
                None => task_store
                    .get(&update.task_id)
                    .await?
                    .ok_or_else(|| A2AError::task_not_found(&update.task_id))?,
            };
            task.status = update.status.clone();
            save_task(task_store, task).await.map(Some)
        }
        StreamResponse::ArtifactUpdate(update) => {
            let mut task = match current_task {
                Some(task) => task,
                None => task_store
                    .get(&update.task_id)
                    .await?
                    .ok_or_else(|| A2AError::task_not_found(&update.task_id))?,
            };
            let artifacts = task.artifacts.get_or_insert_with(Vec::new);
            let existing = artifacts
                .iter_mut()
                .find(|artifact| artifact.artifact_id == update.artifact.artifact_id);
            if update.append.unwrap_or(false) {
                let artifact = existing.ok_or_else(A2AError::invalid_agent_response)?;
                artifact.parts.extend(update.artifact.parts.iter().cloned());
                if let Some(metadata) = &update.artifact.metadata {
                    artifact
                        .metadata
                        .get_or_insert_with(Default::default)
                        .extend(metadata.clone());
                }
            } else if let Some(artifact) = existing {
                *artifact = update.artifact.clone();
            } else {
                artifacts.push(update.artifact.clone());
            }
            save_task(task_store, task).await.map(Some)
        }
        StreamResponse::Message(_) => Ok(current_task),
    }
}

fn subscription_stream(
    receiver: broadcast::Receiver<ExecutionEvent>,
    snapshot_task: Option<Task>,
    min_sequence: u64,
) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
    Box::pin(futures::stream::unfold(
        SubscriptionState {
            receiver,
            snapshot_task,
            min_sequence,
            done: false,
        },
        |mut state| async move {
            if state.done {
                return None;
            }

            if let Some(task) = state.snapshot_task.take() {
                if task.status.state.is_terminal() {
                    state.done = true;
                }
                return Some((Ok(StreamResponse::Task(task)), state));
            }

            loop {
                match state.receiver.recv().await {
                    Ok(event) if event.sequence <= state.min_sequence => continue,
                    Ok(event) => {
                        state.min_sequence = event.sequence;
                        match &event.result {
                            Ok(item) if is_terminal_event(item) => state.done = true,
                            Err(_) => state.done = true,
                            _ => {}
                        }
                        return Some((event.result.clone(), state));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state.done = true;
                        return Some((
                            Err(crate::sanitized_internal_error(
                                "subscription fell behind active execution",
                            )),
                            state,
                        ));
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    ))
}

async fn drive_execution(
    runtime: ExecutionRuntime,
    task_id: TaskId,
    active: Arc<ActiveExecution>,
    exec_ctx: crate::ExecutorContext,
) {
    let mut current_task = {
        let state = active.state.read().await;
        state.snapshot_task.clone()
    };
    let mut stream = runtime.executor.execute(exec_ctx);
    // Push delivery runs in the background. Errors known before a request is
    // sent (URL and header checks, an unreadable config store) fail the event
    // synchronously in both modes (`precheck_push`). A failed delivery is
    // only logged, unless the sender is configured with `fail_on_error`: then
    // it is recorded on the execution, which ends at the first recorded
    // failure (the failure wakes any wait at once and the jobs still queued
    // are skipped). The terminal event, and the end of an execution that
    // stops without one, wait for the task's pending pushes, so no failure is
    // lost after the loop has stopped reading the record.
    let strict = push_is_strict(
        runtime.push_config_store.as_ref(),
        runtime.push_sender.as_ref(),
    );
    let on_push_error: Option<PushErrorSink> = strict.then(|| {
        let active = Arc::clone(&active);
        let sink: PushErrorSink = Arc::new(move |error| active.record_push_failure(error));
        sink
    });
    let abandon = strict.then(|| Arc::clone(&active.push_abandoned));
    // Pushes were enqueued that no later wait has covered yet.
    let mut unflushed = false;
    // The execution already published its final error.
    let mut failed = false;

    while let Some(result) = stream.next().await {
        if active.snapshot_is_terminal().await {
            break;
        }
        if let Some(error) = active.take_push_failure() {
            active.publish(Err(&error), None).await;
            failed = true;
            break;
        }

        match result {
            Ok(mut event) => {
                backfill_status_timestamp(&mut event);
                match apply_event_to_task(runtime.task_store.as_ref(), current_task.clone(), &event)
                    .await
                {
                    Ok(updated_task) => {
                        current_task = updated_task.clone();
                        if let Err(error) = precheck_push(
                            runtime.push_config_store.as_ref(),
                            runtime.push_sender.as_ref(),
                            &task_id,
                        )
                        .await
                        {
                            active.publish(Err(&error), None).await;
                            failed = true;
                            break;
                        }
                        let terminal = is_terminal_event(&event);
                        let wait = strict && terminal;
                        let outcome = enqueue_push(
                            &runtime.push_dispatcher,
                            &task_id,
                            runtime.push_config_store.as_ref(),
                            runtime.push_sender.as_ref(),
                            Some(&event),
                            on_push_error.clone(),
                            abandon.clone(),
                            wait,
                        );
                        if let Some(outcome) = outcome {
                            // Strict terminal event: its own failure, or any
                            // earlier one recorded meanwhile, is published
                            // instead of the event, as before pushes were
                            // queued.
                            unflushed = false;
                            let result = await_push_or_failure(&active, outcome).await;
                            if let Some(error) = active.take_push_failure().or(result.err()) {
                                active.publish(Err(&error), None).await;
                                failed = true;
                                break;
                            }
                        } else {
                            unflushed = strict;
                        }
                        active.publish(Ok(&event), updated_task).await;
                        if terminal {
                            break;
                        }
                    }
                    Err(error) => {
                        active.publish(Err(&error), None).await;
                        failed = true;
                        break;
                    }
                }
            }
            Err(error) => {
                active.publish(Err(&error), None).await;
                failed = true;
                break;
            }
        }
    }

    // The loop ended without a terminal event (the executor stopped, or the
    // task was finished elsewhere): wait for the pushes still in flight so
    // that a failure of one of them is reported instead of only logged.
    if strict && unflushed && !failed {
        let outcome = enqueue_push(
            &runtime.push_dispatcher,
            &task_id,
            runtime.push_config_store.as_ref(),
            runtime.push_sender.as_ref(),
            None,
            None,
            abandon,
            true,
        );
        if let Some(outcome) = outcome {
            let result = await_push_or_failure(&active, outcome).await;
            if let Some(error) = active.take_push_failure().or(result.err()) {
                active.publish(Err(&error), None).await;
            }
        }
    }

    runtime.execution_manager.finish(&task_id, &active).await;
}

/// Transport-agnostic request handler interface.
///
/// This is the core interface consumed by all protocol bindings
/// (JSON-RPC, REST, gRPC). The [`DefaultRequestHandler`] provides a
/// standard implementation that orchestrates task lifecycle, storage,
/// and executor dispatch.
#[async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    async fn send_message(
        &self,
        params: &ServiceParams,
        req: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError>;

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError>;

    async fn get_task(&self, params: &ServiceParams, req: GetTaskRequest)
    -> Result<Task, A2AError>;

    async fn list_tasks(
        &self,
        params: &ServiceParams,
        req: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError>;

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        req: CancelTaskRequest,
    ) -> Result<Task, A2AError>;

    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        req: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError>;

    async fn create_push_config(
        &self,
        params: &ServiceParams,
        req: TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError>;

    async fn get_push_config(
        &self,
        params: &ServiceParams,
        req: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError>;

    async fn list_push_configs(
        &self,
        params: &ServiceParams,
        req: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError>;

    async fn delete_push_config(
        &self,
        params: &ServiceParams,
        req: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError>;

    async fn get_extended_agent_card(
        &self,
        params: &ServiceParams,
        req: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError>;
}

/// Decides whether a request may proceed.
///
/// The handler never treats a non-empty header as a principal. An
/// implementation must validate whatever credential it accepts (token, DID,
/// session) and return [`A2AError`] when that check fails. `task_id` is set
/// when the method addresses one task and is reserved for owner checks.
pub trait RequestAuthorizer: Send + Sync {
    fn authorize(&self, params: &ServiceParams, task_id: Option<&str>) -> Result<(), A2AError>;
}

impl<F> RequestAuthorizer for F
where
    F: Fn(&ServiceParams, Option<&str>) -> Result<(), A2AError> + Send + Sync,
{
    fn authorize(&self, params: &ServiceParams, task_id: Option<&str>) -> Result<(), A2AError> {
        self(params, task_id)
    }
}

/// Default implementation of [`RequestHandler`] that orchestrates
/// task lifecycle management, storage, and executor dispatch.
pub struct DefaultRequestHandler {
    executor: Arc<dyn crate::AgentExecutor>,
    task_store: Arc<dyn crate::TaskStore>,
    execution_manager: Arc<ExecutionManager>,
    push_config_store: Option<Arc<dyn crate::PushConfigStore>>,
    push_sender: Option<Arc<crate::HttpPushSender>>,
    push_dispatcher: Arc<PushDispatcher>,
    capabilities: AgentCapabilities,
    default_input_modes: Vec<String>,
    authorizer: Option<Arc<dyn RequestAuthorizer>>,
    extended_agent_card: Option<Arc<dyn ExtendedAgentCardResolver>>,
}

/// Supplies the authenticated extended Agent Card (§12.4, §10.1).
///
/// A resolver rather than a stored card because §12.4 has the extended card
/// fetched *under a security scheme*: which skills an agent reveals can
/// legitimately differ by caller, and `ServiceParams` is where the caller's
/// credentials arrive. An agent serving one card to everyone can ignore the
/// argument — [`DefaultRequestHandler::with_extended_agent_card`] wraps a
/// plain card for exactly that case.
pub trait ExtendedAgentCardResolver: Send + Sync {
    fn resolve(&self, params: &ServiceParams) -> Result<AgentCard, A2AError>;
}

impl<F> ExtendedAgentCardResolver for F
where
    F: Fn(&ServiceParams) -> Result<AgentCard, A2AError> + Send + Sync,
{
    fn resolve(&self, params: &ServiceParams) -> Result<AgentCard, A2AError> {
        self(params)
    }
}

impl DefaultRequestHandler {
    pub fn new(executor: impl crate::AgentExecutor, task_store: impl crate::TaskStore) -> Self {
        DefaultRequestHandler {
            executor: Arc::new(executor),
            task_store: Arc::new(task_store),
            execution_manager: Arc::new(ExecutionManager::default()),
            push_config_store: None,
            push_sender: None,
            push_dispatcher: PushDispatcher::new(),
            capabilities: AgentCapabilities::default(),
            default_input_modes: Vec::new(),
            authorizer: None,
            extended_agent_card: None,
        }
    }

    /// Serve `card` as the extended Agent Card, identically for every caller.
    ///
    /// Also declares the `extendedAgentCard` capability, since serving one
    /// and advertising it should not be two separate things to remember —
    /// an explicit `with_capabilities(..)` still overrides it either way.
    pub fn with_extended_agent_card(mut self, card: AgentCard) -> Self {
        self.capabilities.extended_agent_card.get_or_insert(true);
        self.with_extended_agent_card_resolver(move |_: &ServiceParams| Ok(card.clone()))
    }

    /// Serve an extended Agent Card computed per caller, so an agent can
    /// reveal different skills to different principals (§12.4).
    pub fn with_extended_agent_card_resolver(
        mut self,
        resolver: impl ExtendedAgentCardResolver + 'static,
    ) -> Self {
        self.capabilities.extended_agent_card.get_or_insert(true);
        self.extended_agent_card = Some(Arc::new(resolver));
        self
    }

    /// Install an authorizer. The default handler does not enforce one.
    pub fn with_authorizer(mut self, authorizer: impl RequestAuthorizer + 'static) -> Self {
        self.authorizer = Some(Arc::new(authorizer));
        self
    }

    fn authorize(&self, params: &ServiceParams, task_id: Option<&str>) -> Result<(), A2AError> {
        match &self.authorizer {
            Some(authorizer) => authorizer.authorize(params, task_id),
            None => Ok(()),
        }
    }

    pub fn with_push_config_store(
        mut self,
        push_config_store: impl crate::PushConfigStore,
    ) -> Self {
        self.push_sender = Some(Arc::new(crate::HttpPushSender::new(None)));
        self.push_config_store = Some(Arc::new(push_config_store));
        // Only a default: an explicit `Some(false)` from `with_capabilities`
        // stands, so the result no longer depends on which builder method was
        // called last.
        self.capabilities.push_notifications.get_or_insert(true);
        self
    }

    pub fn with_push_notifications(
        mut self,
        push_config_store: impl crate::PushConfigStore,
        push_sender: crate::HttpPushSender,
    ) -> Self {
        self.push_config_store = Some(Arc::new(push_config_store));
        self.push_sender = Some(Arc::new(push_sender));
        self.capabilities.push_notifications.get_or_insert(true);
        self
    }

    pub fn with_capabilities(mut self, capabilities: AgentCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Declares the media types incoming message parts may use (§5.1's
    /// `defaultInputModes`). Empty (the default) means unrestricted, so
    /// embedders that never call this see no change in behavior.
    pub fn with_default_input_modes(mut self, modes: impl Into<Vec<String>>) -> Self {
        self.default_input_modes = modes.into();
        self
    }

    /// A part with a declared, non-empty media type that isn't among the
    /// advertised `defaultInputModes` is rejected; a part that declares none
    /// is unrestricted, and so is every part when no modes were declared.
    fn validate_content_types(&self, message: &Message) -> Result<(), A2AError> {
        if self.default_input_modes.is_empty() {
            return Ok(());
        }
        let supported = message.parts.iter().all(|part| {
            part.media_type.as_deref().is_none_or(|media_type| {
                media_type.is_empty() || self.default_input_modes.iter().any(|m| m == media_type)
            })
        });
        if supported {
            Ok(())
        } else {
            Err(A2AError::content_type_not_supported())
        }
    }

    /// §13.3: refuse a capability-gated operation the card does not declare.
    ///
    /// `None` means "not restricted", not "refused". `AgentCapabilities::
    /// default()` leaves every field `None` and most embedders never call
    /// [`Self::with_capabilities`], so treating `None` as a refusal would
    /// break all of them at once. Only an explicit `Some(false)` refuses.
    fn require_capability(
        declared: Option<bool>,
        unsupported: impl FnOnce() -> A2AError,
    ) -> Result<(), A2AError> {
        match declared {
            Some(false) => Err(unsupported()),
            _ => Ok(()),
        }
    }

    fn require_streaming(&self) -> Result<(), A2AError> {
        Self::require_capability(self.capabilities.streaming, || {
            A2AError::unsupported_operation("the agent card does not declare streaming")
        })
    }

    fn require_push_notifications(&self) -> Result<(), A2AError> {
        Self::require_capability(
            self.capabilities.push_notifications,
            A2AError::push_notification_not_supported,
        )
    }

    /// The push-config store, refusing first when the card declares that the
    /// agent does not support push notifications (§13.3). Distinct from
    /// [`Self::push_config_store`], which reports the *deployment* state — a
    /// store that was never supplied — with the same error code.
    fn push_config_store_checked(&self) -> Result<&dyn crate::PushConfigStore, A2AError> {
        self.require_push_notifications()?;
        self.push_config_store()
    }

    fn push_config_store(&self) -> Result<&dyn crate::PushConfigStore, A2AError> {
        self.push_config_store
            .as_deref()
            .ok_or_else(A2AError::push_notification_not_supported)
    }

    async fn load_task(&self, task_id: &str) -> Result<Task, A2AError> {
        self.task_store
            .get(task_id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(task_id))
    }

    async fn prepare_task_for_execution(
        &self,
        req: &SendMessageRequest,
    ) -> Result<(Task, Option<Task>, String), A2AError> {
        // A2A §3.4.2: a client-provided taskId MUST reference an existing task,
        // and client-provided ids for *creating* tasks are not supported. Only
        // an absent taskId may mint a new one.
        let task_id = match req.message.task_id.clone() {
            Some(id) => id,
            None => new_task_id(),
        };
        let stored = self.task_store.get(&task_id).await?;
        if stored.is_none() && req.message.task_id.is_some() {
            return Err(A2AError::task_not_found(&task_id));
        }
        if stored
            .as_ref()
            .is_some_and(|task| task.status.state.is_terminal())
        {
            return Err(A2AError::unsupported_operation(format!(
                "task {task_id} has already reached a terminal state"
            )));
        }

        // A2A §3.4.3: reject a mismatching contextId/taskId pair, and infer
        // contextId from the task when only taskId is given.
        let context_id = match stored.as_ref() {
            Some(task) => {
                if let Some(requested) = req.message.context_id.as_deref() {
                    if requested != task.context_id {
                        return Err(A2AError::invalid_params(format!(
                            "contextId {requested} does not match task {task_id}, \
                             which belongs to context {}",
                            task.context_id
                        )));
                    }
                }
                task.context_id.clone()
            }
            None => req
                .message
                .context_id
                .clone()
                .unwrap_or_else(new_context_id),
        };

        let task = if let Some(mut existing) = stored.clone() {
            // A continuation turn's own incoming message was never otherwise
            // recorded anywhere: the executor only sees it via `ctx.message`
            // for deciding this turn's behavior, and `apply_event_to_task`
            // only ever merges status/artifact deltas onto the snapshot
            // started here, never anything content-derived. Append it so
            // `history` actually accumulates across turns.
            existing
                .history
                .get_or_insert_with(Vec::new)
                .push(req.message.clone());
            existing
        } else {
            let task = Task {
                id: task_id,
                context_id: context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: Some(chrono::Utc::now()),
                },
                artifacts: None,
                history: Some(vec![req.message.clone()]),
                metadata: None,
            };
            self.task_store.create(task.clone()).await?;
            task
        };

        Ok((task, stored, context_id))
    }

    async fn save_request_push_config(
        &self,
        task_id: &str,
        req: &SendMessageRequest,
    ) -> Result<(), A2AError> {
        let Some(config) = req
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.task_push_notification_config.clone())
        else {
            return Ok(());
        };

        let mut config = config;
        config.task_id = task_id.to_string();
        if config.tenant.is_none() {
            config.tenant = req.tenant.clone();
        }
        self.push_config_store_checked()?.save(config).await?;
        Ok(())
    }

    async fn start_execution(
        &self,
        params: &ServiceParams,
        req: SendMessageRequest,
        include_task_snapshot_in_context: bool,
    ) -> Result<(TaskId, BoxStream<'static, Result<StreamResponse, A2AError>>), A2AError> {
        self.validate_content_types(&req.message)?;
        let (task, stored_task, context_id) = self.prepare_task_for_execution(&req).await?;
        let task_id = task.id.clone();
        self.save_request_push_config(&task_id, &req).await?;
        let active = self.execution_manager.start(task.clone()).await?;
        let receiver = active.subscribe();

        let exec_ctx = crate::ExecutorContext {
            message: Some(req.message),
            task_id: task_id.clone(),
            stored_task: if include_task_snapshot_in_context {
                Some(task.clone())
            } else {
                stored_task
            },
            context_id,
            metadata: req.metadata,
            user: None,
            service_params: params.clone(),
            tenant: req.tenant,
        };

        let runtime = ExecutionRuntime {
            executor: Arc::clone(&self.executor),
            task_store: Arc::clone(&self.task_store),
            push_config_store: self.push_config_store.clone(),
            push_sender: self.push_sender.clone(),
            push_dispatcher: Arc::clone(&self.push_dispatcher),
            execution_manager: Arc::clone(&self.execution_manager),
        };
        let active_execution = active.clone();
        let execution_task_id = task_id.clone();

        tokio::spawn(async move {
            drive_execution(runtime, execution_task_id, active_execution, exec_ctx).await;
        });

        Ok((task_id, subscription_stream(receiver, None, 0)))
    }
}

#[async_trait]
impl RequestHandler for DefaultRequestHandler {
    async fn send_message(
        &self,
        params: &ServiceParams,
        req: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        self.authorize(params, req.message.task_id.as_deref())?;
        // ACTS CORE-HIST-003: configuration.historyLength governs this
        // response's own inline task the same way it governs a later
        // GetTask, so it has to be applied here too, not just there.
        let history_length = req
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length);
        let (task_id, mut stream) = self.start_execution(params, req.clone(), true).await?;
        let mut last_event = None;

        while let Some(item) = stream.next().await {
            let event = item?;

            if let Some(interrupt_task_id) = should_interrupt_non_streaming(&req, &event) {
                let mut task = self.load_task(&interrupt_task_id).await?;
                apply_history_length(&mut task, history_length);
                return Ok(SendMessageResponse::Task(task));
            }

            match event {
                StreamResponse::Message(message) => {
                    return Ok(SendMessageResponse::Message(message));
                }
                other => last_event = Some(other),
            }
        }

        match last_event {
            Some(StreamResponse::Task(mut task)) => {
                apply_history_length(&mut task, history_length);
                Ok(SendMessageResponse::Task(task))
            }
            Some(StreamResponse::StatusUpdate(update)) => {
                let mut task = self.load_task(&update.task_id).await?;
                apply_history_length(&mut task, history_length);
                Ok(SendMessageResponse::Task(task))
            }
            Some(StreamResponse::ArtifactUpdate(update)) => {
                let mut task = self.load_task(&update.task_id).await?;
                apply_history_length(&mut task, history_length);
                Ok(SendMessageResponse::Task(task))
            }
            Some(StreamResponse::Message(message)) => Ok(SendMessageResponse::Message(message)),
            None => {
                let mut task = self.load_task(&task_id).await?;
                apply_history_length(&mut task, history_length);
                Ok(SendMessageResponse::Task(task))
            }
        }
    }

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.authorize(params, req.message.task_id.as_deref())?;
        self.require_streaming()?;
        let (_, stream) = self.start_execution(params, req, false).await?;
        Ok(stream)
    }

    async fn get_task(
        &self,
        params: &ServiceParams,
        req: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        self.authorize(params, Some(&req.id))?;
        let mut task = self
            .task_store
            .get(&req.id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(&req.id))?;
        apply_history_length(&mut task, req.history_length);
        Ok(task)
    }

    /// Bounds the page twice, and neither is redundant: `TaskStore` is a
    /// public trait.
    ///
    /// Clamping `page_size` before the call bounds a store that honours it
    /// -- the ordinary case, and the one that turns `pageSize=999999999`
    /// into a real query. Truncating the response bounds a store that
    /// ignores it, which cannot be detected from here.
    ///
    /// On truncation the store's `next_page_token` is left alone: paging is
    /// the store's own scheme (the in-tree stores use offsets, another may
    /// use an opaque cursor) so no correct token can be synthesised. See
    /// [`TaskStore::list`].
    async fn list_tasks(
        &self,
        params: &ServiceParams,
        req: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        self.authorize(params, None)?;
        let page_size = resolve_page_size(req.page_size);
        let req = ListTasksRequest {
            page_size: Some(page_size as i32),
            ..req
        };
        let mut response = self.task_store.list(&req).await?;
        response.tasks.truncate(page_size);
        for task in &mut response.tasks {
            apply_history_length(task, req.history_length);
        }
        Ok(response)
    }

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        req: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        self.authorize(params, Some(&req.id))?;
        let task = self.load_task(&req.id).await?;

        // Idempotent: re-cancelling an already-canceled task is a no-op that
        // returns the current task (matching a2a-go). Other terminal states
        // are still not cancelable, per A2A and a2a-cli SPEC.md §10.4.
        if task.status.state == TaskState::Canceled {
            return Ok(task);
        }
        if task.status.state.is_terminal() {
            return Err(A2AError::task_not_cancelable(&req.id));
        }

        // Atomically transition the task to CANCELED so two concurrent cancel
        // requests cannot both pass the check-then-act window.
        let task = match self.task_store.begin_cancel(&req.id).await {
            Ok(task) => task,
            Err(error) if error.code == error_code::TASK_NOT_CANCELABLE => {
                // Raced with another cancel or with task completion. Keep the
                // same semantics as the upfront check: a task another cancel
                // already moved to CANCELED is returned (idempotent); any
                // other terminal state is still not cancelable.
                let raced = self.load_task(&req.id).await?;
                if raced.status.state == TaskState::Canceled {
                    return Ok(raced);
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        let active_execution = self.execution_manager.get(&req.id).await;

        let exec_ctx = crate::ExecutorContext {
            message: None,
            task_id: req.id.clone(),
            stored_task: Some(task.clone()),
            context_id: task.context_id.clone(),
            metadata: req.metadata,
            user: None,
            service_params: params.clone(),
            tenant: req.tenant,
        };

        let mut stream = self.executor.cancel(exec_ctx);
        let mut current_task = Some(task);

        while let Some(event) = stream.next().await {
            match event {
                Ok(mut event) => {
                    backfill_status_timestamp(&mut event);
                    let updated_task =
                        apply_event_to_task(self.task_store.as_ref(), current_task.clone(), &event)
                            .await?;
                    current_task = updated_task.clone();

                    // Delivery is queued: a slow or failing webhook can
                    // neither delay nor fail the cancellation, unless the
                    // sender is strict (`fail_on_error`). Then a
                    // cancellation waits for the pushes queued ahead of its
                    // own (pushes that a recorded strict failure abandoned
                    // are skipped, which can shorten the wait), then for its
                    // own push, which stops at its first failed request, and
                    // returns that error; errors of pushes the execution
                    // queued earlier go to that execution. Errors known
                    // before a request is sent fail the cancellation in both
                    // modes.
                    precheck_push(
                        self.push_config_store.as_ref(),
                        self.push_sender.as_ref(),
                        &req.id,
                    )
                    .await?;
                    let wait =
                        push_is_strict(self.push_config_store.as_ref(), self.push_sender.as_ref());
                    let outcome = enqueue_push(
                        &self.push_dispatcher,
                        &req.id,
                        self.push_config_store.as_ref(),
                        self.push_sender.as_ref(),
                        Some(&event),
                        None,
                        None,
                        wait,
                    );
                    if let Some(outcome) = outcome {
                        await_push(outcome).await?;
                    }

                    if let Some(active) = &active_execution {
                        active.publish(Ok(&event), updated_task).await;
                    }

                    if is_terminal_event(&event) {
                        break;
                    }
                }
                Err(error) => {
                    if let Some(active) = &active_execution {
                        active.publish(Err(&error), None).await;
                    }
                    return Err(error);
                }
            }
        }

        if let Some(active) = active_execution {
            self.execution_manager.finish(&req.id, &active).await;
        }

        self.load_task(&req.id).await
    }

    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        req: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.authorize(params, Some(&req.id))?;
        self.require_streaming()?;
        if let Some((receiver, snapshot_task, sequence)) =
            self.execution_manager.resubscribe(&req.id).await
        {
            return Ok(subscription_stream(receiver, snapshot_task, sequence));
        }

        // A registry miss also happens once a task finishes and its
        // execution is cleaned up, so it doesn't by itself mean the task
        // never existed -- check the store to tell the two apart before
        // reporting TaskNotFoundError.
        if let Some(task) = self.task_store.get(&req.id).await? {
            if task.status.state.is_terminal() {
                return Err(A2AError::unsupported_operation(format!(
                    "task {} has already reached a terminal state",
                    req.id
                )));
            }
        }
        Err(A2AError::task_not_found(&req.id))
    }

    async fn create_push_config(
        &self,
        params: &ServiceParams,
        req: TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.authorize(params, Some(&req.task_id))?;
        self.push_config_store_checked()?.save(req).await
    }

    async fn get_push_config(
        &self,
        params: &ServiceParams,
        req: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.authorize(params, Some(&req.task_id))?;
        self.push_config_store_checked()?
            .get(&req.task_id, &req.id)
            .await
    }

    async fn list_push_configs(
        &self,
        params: &ServiceParams,
        req: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        self.authorize(params, Some(&req.task_id))?;
        let mut configs = self.push_config_store_checked()?.list(&req.task_id).await?;
        configs.sort_by(|left, right| left.id.cmp(&right.id));

        // Paging for push configs is done here, not in the store: the store
        // is asked for every config for the task and the page is cut from
        // that. PushConfigStore is public, so this clamp is what bounds the
        // response for an implementation with no per-task limit of its own.
        let page_size = resolve_page_size(req.page_size);
        let start = if let Some(ref token) = req.page_token {
            token
                .parse::<usize>()
                .map_err(|_| A2AError::invalid_params("invalid page token"))?
        } else {
            0
        };
        let start = start.min(configs.len());
        let end = (start + page_size).min(configs.len());
        let next_page_token = (end < configs.len()).then(|| end.to_string());

        Ok(ListTaskPushNotificationConfigsResponse {
            configs: configs[start..end].to_vec(),
            next_page_token,
        })
    }

    async fn delete_push_config(
        &self,
        params: &ServiceParams,
        req: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        self.authorize(params, Some(&req.task_id))?;
        self.push_config_store_checked()?
            .delete(&req.task_id, &req.id)
            .await
    }

    async fn get_extended_agent_card(
        &self,
        params: &ServiceParams,
        _req: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        self.authorize(params, None)?;
        Self::require_capability(self.capabilities.extended_agent_card, || {
            A2AError::unsupported_operation(
                "the agent card does not declare an extended agent card",
            )
        })?;
        match &self.extended_agent_card {
            Some(resolver) => resolver.resolve(params),
            // A2A defines a code for exactly this condition.
            // UNSUPPORTED_OPERATION would say the agent does not do extended
            // cards at all, when the truth is that this deployment has not
            // configured one — the client can act on that difference.
            None => Err(A2AError::extended_card_not_configured()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::ExecutorContext;
    use crate::pagination::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
    use crate::push::{InMemoryPushConfigStore, PushConfigStore};
    use crate::task_store::{InMemoryTaskStore, TaskStore, TaskVersion};

    use crate::test_util::install_crypto_provider;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode, header},
        routing::post,
    };
    use futures::stream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};
    use tokio::{
        net::TcpListener,
        sync::{Notify, mpsc, oneshot},
        time::{Duration, timeout},
    };

    struct EchoExecutor;

    struct PushEventExecutor;

    struct ResumableExecutor {
        release: Arc<Notify>,
    }

    #[derive(Debug)]
    struct CapturedPush {
        authorization: Option<String>,
        notification_token: Option<String>,
        event: StreamResponse,
    }

    impl crate::AgentExecutor for EchoExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let task = Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: ctx.message,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            Box::pin(stream::once(async move { Ok(StreamResponse::Task(task)) }))
        }

        fn cancel(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let task = Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            Box::pin(stream::once(async move { Ok(StreamResponse::Task(task)) }))
        }
    }

    impl crate::AgentExecutor for PushEventExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let working = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            });
            let completed = StreamResponse::Task(Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: ctx.message,
                    timestamp: None,
                },
                artifacts: None,
                history: ctx.stored_task.and_then(|task| task.history),
                metadata: None,
            });

            Box::pin(stream::iter(vec![Ok(working), Ok(completed)]))
        }

        fn cancel(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let task = Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            Box::pin(stream::once(async move { Ok(StreamResponse::Task(task)) }))
        }
    }

    impl crate::AgentExecutor for ResumableExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let release = self.release.clone();
            let working_task = Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: ctx.stored_task.and_then(|task| task.history),
                metadata: None,
            };
            let completed_task = Task {
                id: working_task.id.clone(),
                context_id: working_task.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: working_task.history.clone(),
                metadata: None,
            };

            Box::pin(stream::unfold(
                (Some(working_task), Some((release, completed_task))),
                |(working_task, completion)| async move {
                    if let Some(task) = working_task {
                        return Some((Ok(StreamResponse::Task(task)), (None, completion)));
                    }

                    if let Some((release, task)) = completion {
                        release.notified().await;
                        return Some((Ok(StreamResponse::Task(task)), (None, None)));
                    }

                    None
                },
            ))
        }

        fn cancel(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let task = Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            Box::pin(stream::once(async move { Ok(StreamResponse::Task(task)) }))
        }
    }

    /// Mirrors itk's own `tck-multi-turn` ACTS behavior: only ever emits a
    /// `StatusUpdate`, never a full `Task`, so a test against it exercises
    /// exactly the path a real executor that never touches `history` relies
    /// on the server to handle.
    struct MultiTurnExecutor;

    impl crate::AgentExecutor for MultiTurnExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let done = ctx
                .message
                .as_ref()
                .and_then(Message::text)
                .is_some_and(|text| text.trim().eq_ignore_ascii_case("done"));
            let state = if done {
                TaskState::Completed
            } else {
                TaskState::InputRequired
            };
            let update = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            });
            Box::pin(stream::once(async move { Ok(update) }))
        }

        fn cancel(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let task = Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            Box::pin(stream::once(async move { Ok(StreamResponse::Task(task)) }))
        }
    }

    /// A `TaskStore` that behaves exactly like `InMemoryTaskStore` except
    /// for `list`, which it drives from the fields below.
    ///
    /// `TaskStore` is public, so nothing obliges a third-party
    /// implementation to bound its own response. Only a decorator can model
    /// that; everything else delegates, so a cap test cannot accidentally
    /// depend on stub behaviour.
    struct PagingTaskStore {
        inner: InMemoryTaskStore,
        count: usize,
        /// `true` models a well-behaved store, bounded by the handler
        /// clamping the request; `false` models one that ignores
        /// `page_size`, bounded only by the handler truncating the response.
        honour_page_size: bool,
        /// The `page_size` the handler actually asked for. Recorded because
        /// the response bound alone cannot distinguish a clamped request
        /// from an unclamped one -- both end up 100 items wide.
        seen_page_size: Arc<AtomicI32>,
        /// Continuation token the store reports, so truncation's handling of
        /// it can be observed.
        next_page_token: String,
    }

    impl PagingTaskStore {
        fn new(count: usize, honour_page_size: bool) -> Self {
            Self {
                inner: InMemoryTaskStore::new(),
                count,
                honour_page_size,
                seen_page_size: Arc::new(AtomicI32::new(-1)),
                next_page_token: String::new(),
            }
        }

        fn with_next_page_token(mut self, token: &str) -> Self {
            self.next_page_token = token.to_string();
            self
        }
    }

    #[async_trait]
    impl TaskStore for PagingTaskStore {
        async fn create(&self, task: Task) -> Result<TaskVersion, A2AError> {
            self.inner.create(task).await
        }

        async fn update(&self, task: Task) -> Result<TaskVersion, A2AError> {
            self.inner.update(task).await
        }

        async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
            self.inner.get(task_id).await
        }

        async fn begin_cancel(&self, task_id: &str) -> Result<Task, A2AError> {
            self.inner.begin_cancel(task_id).await
        }

        async fn list(&self, req: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
            self.seen_page_size
                .store(req.page_size.unwrap_or(-1), Ordering::SeqCst);
            let served = if self.honour_page_size {
                req.page_size.unwrap_or(i32::MAX).max(0) as usize
            } else {
                self.count
            }
            .min(self.count);
            let tasks = (0..served)
                .map(|i| Task {
                    id: format!("t-{i:04}"),
                    context_id: "c1".into(),
                    status: TaskStatus {
                        state: TaskState::Completed,
                        message: None,
                        timestamp: None,
                    },
                    artifacts: None,
                    history: None,
                    metadata: None,
                })
                .collect::<Vec<_>>();
            let total = tasks.len() as i32;
            Ok(ListTasksResponse {
                tasks,
                next_page_token: self.next_page_token.clone(),
                page_size: total,
                total_size: total,
            })
        }
    }

    /// The push-config equivalent, and the only way to reach the handler's
    /// page cap on that path: `InMemoryPushConfigStore` caps a task at
    /// `MAX_PUSH_CONFIGS_PER_TASK` (50), below the page cap of 100, so
    /// nothing routed through it can make the clamp bind. Everything but
    /// `list` delegates.
    struct PagingPushConfigStore {
        inner: InMemoryPushConfigStore,
        count: usize,
    }

    impl PagingPushConfigStore {
        fn new(count: usize) -> Self {
            Self {
                inner: InMemoryPushConfigStore::new(),
                count,
            }
        }
    }

    #[async_trait]
    impl crate::PushConfigStore for PagingPushConfigStore {
        async fn save(
            &self,
            config: TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            self.inner.save(config).await
        }

        async fn get(
            &self,
            task_id: &str,
            config_id: &str,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            self.inner.get(task_id, config_id).await
        }

        async fn list(&self, task_id: &str) -> Result<Vec<TaskPushNotificationConfig>, A2AError> {
            Ok((0..self.count)
                .map(|i| TaskPushNotificationConfig {
                    task_id: task_id.to_string(),
                    url: format!("https://example.com/hook/{i}"),
                    id: Some(format!("cfg-{i:04}")),
                    token: None,
                    authentication: None,
                    tenant: None,
                })
                .collect())
        }

        async fn delete(&self, task_id: &str, config_id: &str) -> Result<(), A2AError> {
            self.inner.delete(task_id, config_id).await
        }

        async fn delete_all(&self, task_id: &str) -> Result<(), A2AError> {
            self.inner.delete_all(task_id).await
        }
    }

    /// Pre-create a task so a message may legitimately reference it: A2A
    /// §3.4.2 forbids client-provided taskIds for *creating* tasks.
    async fn seed_task(handler: &DefaultRequestHandler, task_id: &str, context_id: &str) {
        handler
            .task_store
            .create(Task {
                id: task_id.into(),
                context_id: context_id.into(),
                status: TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
            .await
            .unwrap();
    }

    fn make_handler() -> DefaultRequestHandler {
        DefaultRequestHandler::new(EchoExecutor, InMemoryTaskStore::new())
    }

    fn make_handler_with_push_configs() -> DefaultRequestHandler {
        DefaultRequestHandler::new(EchoExecutor, InMemoryTaskStore::new())
            .with_push_config_store(InMemoryPushConfigStore::new())
    }

    fn make_push_delivery_handler() -> DefaultRequestHandler {
        // URL validation is disabled because the test webhook runs on
        // 127.0.0.1; the default HttpPushSender rejects loopback targets.
        DefaultRequestHandler::new(PushEventExecutor, InMemoryTaskStore::new())
            .with_push_notifications(
                InMemoryPushConfigStore::new(),
                crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                    validate_urls: false,
                    ..Default::default()
                })),
            )
    }

    fn make_resumable_handler() -> (DefaultRequestHandler, Arc<Notify>) {
        let release = Arc::new(Notify::new());
        (
            DefaultRequestHandler::new(
                ResumableExecutor {
                    release: release.clone(),
                },
                InMemoryTaskStore::new(),
            ),
            release,
        )
    }

    fn make_message() -> Message {
        Message::new(Role::User, vec![Part::text("hello")])
    }

    async fn capture_push(
        State(sender): State<mpsc::UnboundedSender<CapturedPush>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        let captured = CapturedPush {
            authorization: headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            notification_token: headers
                .get("A2A-Notification-Token")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            event: serde_json::from_slice(&body).unwrap(),
        };
        sender.send(captured).unwrap();
        StatusCode::ACCEPTED
    }

    async fn start_push_webhook() -> (
        String,
        mpsc::UnboundedReceiver<CapturedPush>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let app = Router::new()
            .route("/", post(capture_push))
            .with_state(sender);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        (format!("http://{address}/"), receiver, shutdown_tx, server)
    }

    async fn next_push(receiver: &mut mpsc::UnboundedReceiver<CapturedPush>) -> CapturedPush {
        timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// Emits `count` working updates, each tagged with its index in the event
    /// metadata, and then completes the task.
    struct IndexedEventsExecutor {
        count: u64,
        /// Pause before each event, to let background work run in between.
        gap: Duration,
    }

    impl crate::AgentExecutor for IndexedEventsExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let mut events = Vec::new();
            for index in 0..self.count {
                events.push(Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                    task_id: ctx.task_id.clone(),
                    context_id: ctx.context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: None,
                    },
                    metadata: Some(HashMap::from([("i".to_owned(), serde_json::json!(index))])),
                })));
            }
            events.push(Ok(StreamResponse::Task(Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })));
            let gap = self.gap;
            Box::pin(stream::iter(events).then(move |event| async move {
                tokio::time::sleep(gap).await;
                event
            }))
        }

        fn cancel(
            &self,
            _ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            Box::pin(stream::empty())
        }
    }

    /// Webhook that answers only after `delay`.
    async fn slow_push(State(delay): State<Duration>) -> StatusCode {
        tokio::time::sleep(delay).await;
        StatusCode::ACCEPTED
    }

    /// Webhook that records the index of every event it receives. Events with
    /// an even index are answered slowly and odd ones at once, so a sender
    /// that delivered concurrently would reorder them.
    async fn indexed_push(
        State(sender): State<mpsc::UnboundedSender<u64>>,
        body: Bytes,
    ) -> StatusCode {
        let event: StreamResponse = serde_json::from_slice(&body).unwrap();
        let index = match event {
            StreamResponse::StatusUpdate(update) => update
                .metadata
                .and_then(|metadata| metadata.get("i").and_then(serde_json::Value::as_u64))
                .unwrap(),
            _ => u64::MAX,
        };
        if index % 2 == 0 {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        sender.send(index).unwrap();
        StatusCode::ACCEPTED
    }

    async fn serve(app: Router) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{address}/"), shutdown_tx, server)
    }

    fn local_push_handler(executor: impl crate::AgentExecutor) -> DefaultRequestHandler {
        // URL validation is off because the test webhook is on 127.0.0.1.
        DefaultRequestHandler::new(executor, InMemoryTaskStore::new()).with_push_notifications(
            InMemoryPushConfigStore::new(),
            crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                validate_urls: false,
                ..Default::default()
            })),
        )
    }

    fn streaming_request(task_id: &str) -> SendMessageRequest {
        let mut message = make_message();
        message.task_id = Some(task_id.into());
        message.context_id = Some(format!("ctx-{task_id}"));
        SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    #[tokio::test]
    async fn slow_webhook_does_not_block_streaming() {
        install_crypto_provider();
        let app = Router::new()
            .route("/", post(slow_push))
            .with_state(Duration::from_secs(2));
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = local_push_handler(IndexedEventsExecutor {
            count: 3,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-slow", "ctx-t-slow").await;
        let mut config = push_config("t-slow");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let started = std::time::Instant::now();
        let mut events = handler
            .send_streaming_message(&params, streaming_request("t-slow"))
            .await
            .unwrap();
        let mut received = 0;
        while let Some(event) = events.next().await {
            event.unwrap();
            received += 1;
        }
        let elapsed = started.elapsed();

        // Four events, each pushed to a webhook that takes 2s: the stream
        // must finish long before even the first push has completed.
        assert_eq!(received, 4);
        assert!(
            elapsed < Duration::from_millis(1000),
            "streaming was delayed by the webhook: {elapsed:?}"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn push_delivery_order_is_preserved_per_task() {
        install_crypto_provider();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let app = Router::new()
            .route("/", post(indexed_push))
            .with_state(sender);
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = local_push_handler(IndexedEventsExecutor {
            count: 12,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-order", "ctx-t-order").await;
        let mut config = push_config("t-order");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let mut events = handler
            .send_streaming_message(&params, streaming_request("t-order"))
            .await
            .unwrap();
        while let Some(event) = events.next().await {
            event.unwrap();
        }

        let mut seen = Vec::new();
        while seen.len() < 13 {
            let index = timeout(Duration::from_secs(5), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            seen.push(index);
        }
        let mut expected: Vec<u64> = (0..12).collect();
        expected.push(u64::MAX);
        assert_eq!(seen, expected);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// Emits one working update, then waits until the webhook has answered at
    /// least once before it completes the task. No timing is involved: the
    /// terminal event is produced only after a delivery attempt has finished.
    struct GatedExecutor {
        answered: Arc<Notify>,
    }

    impl crate::AgentExecutor for GatedExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let working = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            });
            let answered = Arc::clone(&self.answered);
            let completed = StreamResponse::Task(Task {
                id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            });
            Box::pin(
                stream::once(async move { Ok(working) }).chain(stream::once(async move {
                    answered.notified().await;
                    Ok(completed)
                })),
            )
        }

        fn cancel(
            &self,
            _ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            Box::pin(stream::empty())
        }
    }

    /// Webhook that signals `answered` and then refuses the push.
    async fn rejecting_push(State(answered): State<Arc<Notify>>) -> StatusCode {
        answered.notify_one();
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn strict_push_handler(executor: impl crate::AgentExecutor) -> DefaultRequestHandler {
        DefaultRequestHandler::new(executor, InMemoryTaskStore::new()).with_push_notifications(
            InMemoryPushConfigStore::new(),
            crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                validate_urls: false,
                fail_on_error: true,
                retry: crate::RetryPolicy::none(),
                ..Default::default()
            })),
        )
    }

    fn completed_task_event(events: &[Result<StreamResponse, A2AError>]) -> bool {
        events.iter().any(|event| {
            matches!(event, Ok(StreamResponse::Task(task)) if task.status.state == TaskState::Completed)
        })
    }

    #[tokio::test]
    async fn failed_push_with_fail_on_error_ends_the_execution() {
        install_crypto_provider();
        let answered = Arc::new(Notify::new());
        let app = Router::new()
            .route("/", post(rejecting_push))
            .with_state(Arc::clone(&answered));
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = strict_push_handler(GatedExecutor { answered });
        let params = ServiceParams::new();
        seed_task(&handler, "t-fail", "ctx-t-fail").await;
        let mut config = push_config("t-fail");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-fail"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        // The failure is not lost, whichever event it was noticed at: the
        // stream ends with an error and never reports the task as completed.
        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        assert!(!completed_task_event(&events), "{events:?}");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fail_on_error_surfaces_a_failed_push_of_the_terminal_event() {
        install_crypto_provider();
        async fn reject() -> StatusCode {
            StatusCode::BAD_REQUEST
        }
        let (url, shutdown_tx, server) = serve(Router::new().route("/", post(reject))).await;
        // No events before the terminal one: the failure can only be noticed
        // after the last event has been handed to the dispatcher.
        let handler = strict_push_handler(IndexedEventsExecutor {
            count: 0,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-term", "ctx-t-term").await;
        let mut config = push_config("t-term");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-term"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        assert!(!completed_task_event(&events), "{events:?}");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fail_on_error_reports_events_dropped_from_a_full_queue() {
        install_crypto_provider();
        async fn counting_push(State(sender): State<mpsc::UnboundedSender<()>>) -> StatusCode {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = sender.send(());
            StatusCode::ACCEPTED
        }
        let (tx, _rx) = mpsc::unbounded_channel();
        let app = Router::new().route("/", post(counting_push)).with_state(tx);
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = strict_push_handler(IndexedEventsExecutor {
            count: 200,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-drop", "ctx-t-drop").await;
        let mut config = push_config("t-drop");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-drop"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        let error = events
            .iter()
            .find_map(|event| event.as_ref().err())
            .unwrap_or_else(|| {
                panic!(
                    "a dropped push event was not reported: {} events",
                    events.len()
                )
            });
        assert!(
            error.message.contains("push notification queue full"),
            "the error must name the condition: {error:?}"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fail_on_error_cancel_reports_a_failed_push() {
        install_crypto_provider();
        async fn reject() -> StatusCode {
            StatusCode::BAD_GATEWAY
        }
        let (url, shutdown_tx, server) = serve(Router::new().route("/", post(reject))).await;
        let handler = strict_push_handler(PushEventExecutor);
        let params = ServiceParams::new();
        seed_task(&handler, "t-cancel-strict", "ctx-t-cancel-strict").await;
        let mut config = push_config("t-cancel-strict");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let result = handler
            .cancel_task(
                &params,
                CancelTaskRequest {
                    id: "t-cancel-strict".into(),
                    metadata: None,
                    tenant: None,
                },
            )
            .await;
        assert!(result.is_err(), "{result:?}");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// Emits one working update and stops without a terminal event.
    struct OneWorkingExecutor;

    impl crate::AgentExecutor for OneWorkingExecutor {
        fn execute(
            &self,
            ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            Box::pin(stream::once(async move {
                Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                    task_id: ctx.task_id.clone(),
                    context_id: ctx.context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: None,
                    },
                    metadata: None,
                }))
            }))
        }

        fn cancel(
            &self,
            _ctx: ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            Box::pin(stream::empty())
        }
    }

    /// The run stops after one working event, without a terminal event, and
    /// the webhook rejects 200 ms later, after the loop ended: the end-of-run
    /// barrier is the only thing that can still report the failure.
    #[tokio::test]
    async fn strict_run_without_terminal_reports_failure() {
        install_crypto_provider();
        async fn late_reject() -> StatusCode {
            tokio::time::sleep(Duration::from_millis(200)).await;
            StatusCode::BAD_REQUEST
        }
        let (url, shutdown_tx, server) = serve(Router::new().route("/", post(late_reject))).await;
        let handler = strict_push_handler(OneWorkingExecutor);
        let params = ServiceParams::new();
        seed_task(&handler, "t-bar", "ctx-t-bar").await;
        let mut config = push_config("t-bar");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-bar"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        assert!(events.last().is_some_and(Result::is_err), "{events:?}");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// With the flag off a failed delivery is only logged: the execution
    /// completes and no error reaches the subscriber.
    #[tokio::test]
    async fn nonstrict_delivery_error_is_only_logged() {
        install_crypto_provider();
        async fn reject() -> StatusCode {
            StatusCode::BAD_REQUEST
        }
        let (url, shutdown_tx, server) = serve(Router::new().route("/", post(reject))).await;
        let handler = local_push_handler(IndexedEventsExecutor {
            count: 3,
            gap: Duration::from_millis(30),
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-ns", "ctx-t-ns").await;
        let mut config = push_config("t-ns");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-ns"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        assert!(events.iter().all(Result::is_ok), "{events:?}");
        assert!(completed_task_event(&events), "{events:?}");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// An error known before any request is sent (here a push URL on a blocked
    /// host) fails the event synchronously even with the flag off, as it did
    /// when delivery was inline, instead of surfacing at an arbitrary later
    /// event or never. The executor emits only a terminal event, which would
    /// otherwise be lost.
    #[tokio::test]
    async fn nonstrict_precheck_error_fails_the_event_synchronously() {
        install_crypto_provider();
        let handler = DefaultRequestHandler::new(
            IndexedEventsExecutor {
                count: 0,
                gap: Duration::ZERO,
            },
            InMemoryTaskStore::new(),
        )
        .with_push_notifications(
            InMemoryPushConfigStore::new(),
            crate::HttpPushSender::new(None),
        );
        let params = ServiceParams::new();
        seed_task(&handler, "t-pre", "ctx-t-pre").await;
        let mut config = push_config("t-pre");
        config.url = "http://169.254.169.254/hook".into();
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-pre"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        let error = events
            .iter()
            .find_map(|event| event.as_ref().err())
            .unwrap_or_else(|| panic!("the blocked URL was not reported: {events:?}"));
        assert!(error.message.contains("blocked host"), "{error:?}");
        assert!(!completed_task_event(&events), "{events:?}");
    }

    /// A strict sender with a 1 s request timeout and `configs` configs on a
    /// webhook that never answers, with ten events queued. Returns the
    /// stream and how long it took to end.
    async fn strict_run_against_a_silent_webhook(
        task_id: &str,
        configs: usize,
    ) -> (Vec<Result<StreamResponse, A2AError>>, Duration) {
        install_crypto_provider();
        async fn never_answers() -> StatusCode {
            tokio::time::sleep(Duration::from_secs(60)).await;
            StatusCode::ACCEPTED
        }
        let (url, _shutdown_tx, _server) =
            serve(Router::new().route("/", post(never_answers))).await;
        let handler = DefaultRequestHandler::new(
            IndexedEventsExecutor {
                count: 10,
                gap: Duration::ZERO,
            },
            InMemoryTaskStore::new(),
        )
        .with_push_notifications(
            InMemoryPushConfigStore::new(),
            crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                validate_urls: false,
                fail_on_error: true,
                timeout: Duration::from_secs(1),
                retry: crate::RetryPolicy::none(),
                ..Default::default()
            })),
        );
        let params = ServiceParams::new();
        seed_task(&handler, task_id, &format!("ctx-{task_id}")).await;
        for index in 0..configs {
            let mut config = push_config(task_id);
            config.id = Some(format!("cfg-{index}"));
            config.url = url.clone();
            handler.create_push_config(&params, config).await.unwrap();
        }

        let started = std::time::Instant::now();
        let events = handler
            .send_streaming_message(&params, streaming_request(task_id))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        (events, started.elapsed())
    }

    /// 32 configs on a webhook that never answers, a 1 s request timeout and
    /// ten queued events: every request fails at its own timeout, and the
    /// execution ends with the error one request time after the failed
    /// requests were sent (the first 4 start together and none succeeds, so
    /// nothing earlier is still awaited), bounded here by 1.8 s. With
    /// successful requests of the same event ahead of the failure it can take
    /// up to floor(k / 4) + 1 request times for k configs ahead of the failing
    /// request. Waiting for every config of the event would take
    /// ceil(32 / 4) = 8 request times (8 s), the whole queue far longer.
    #[tokio::test]
    async fn strict_failure_ends_the_execution_promptly() {
        let (events, elapsed) = strict_run_against_a_silent_webhook("t-prompt", 32).await;

        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        assert!(!completed_task_event(&events), "{events:?}");
        assert!(
            elapsed < Duration::from_millis(1800),
            "a strict failure did not end the execution within one request time \
             (32 configs, 1 s timeout): {elapsed:?}"
        );
    }

    /// The same with 16 configs, bounded by 1.5 s (4 request times if the
    /// event were awaited whole).
    #[tokio::test]
    async fn strict_failure_with_16_configs_ends_within_one_request_time() {
        let (events, elapsed) = strict_run_against_a_silent_webhook("t-prompt16", 16).await;

        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        assert!(
            elapsed < Duration::from_millis(1500),
            "a strict failure did not end the execution within one request time \
             (16 configs, 1 s timeout): {elapsed:?}"
        );
    }

    /// One config answers 400 at once and a second one only after 5 s: the
    /// failed request ends the execution, the second one is not awaited.
    #[tokio::test]
    async fn strict_failure_does_not_wait_for_the_other_configs_of_its_event() {
        install_crypto_provider();
        async fn reject() -> StatusCode {
            StatusCode::BAD_REQUEST
        }
        async fn slow() -> StatusCode {
            tokio::time::sleep(Duration::from_secs(5)).await;
            StatusCode::ACCEPTED
        }
        let (url, shutdown_tx, server) = serve(
            Router::new()
                .route("/fail", post(reject))
                .route("/slow", post(slow)),
        )
        .await;
        let handler = strict_push_handler(IndexedEventsExecutor {
            count: 0,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-two", "ctx-t-two").await;
        for (id, path) in [("a-slow", "slow"), ("b-fail", "fail")] {
            let mut config = push_config("t-two");
            config.id = Some(id.into());
            config.url = format!("{url}{path}");
            handler.create_push_config(&params, config).await.unwrap();
        }

        let started = std::time::Instant::now();
        let events = handler
            .send_streaming_message(&params, streaming_request("t-two"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let elapsed = started.elapsed();

        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        assert!(
            elapsed < Duration::from_secs(1),
            "the failed request did not end the execution: {elapsed:?}"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// Ten events 300 ms apart and a webhook that answers 400 at once: the
    /// failure is noticed while events are still arriving, so the stream ends
    /// at the next event with fewer than ten of them published. Without the
    /// per-event check the run would go on to the terminal event (3.3 s).
    #[tokio::test]
    async fn strict_failure_ends_the_execution_at_the_next_event() {
        install_crypto_provider();
        async fn reject() -> StatusCode {
            StatusCode::BAD_REQUEST
        }
        let (url, shutdown_tx, server) = serve(Router::new().route("/", post(reject))).await;
        let handler = strict_push_handler(IndexedEventsExecutor {
            count: 10,
            gap: Duration::from_millis(300),
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-next", "ctx-t-next").await;
        let mut config = push_config("t-next");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let started = std::time::Instant::now();
        let events = handler
            .send_streaming_message(&params, streaming_request("t-next"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let elapsed = started.elapsed();

        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        let published = events.iter().filter(|event| event.is_ok()).count();
        assert!(published < 10, "{published} events were published");
        assert!(
            elapsed < Duration::from_millis(1500),
            "the failure was not noticed at the next event: {elapsed:?}"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// The first request fails and every later one is counted: the pushes of
    /// the events already queued behind the failed one are skipped, not sent
    /// after the execution has ended.
    #[tokio::test]
    async fn strict_failure_skips_the_pushes_queued_behind_it() {
        install_crypto_provider();
        async fn fail_first(State(hits): State<Arc<AtomicI32>>) -> StatusCode {
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::ACCEPTED
            }
        }
        let hits = Arc::new(AtomicI32::new(0));
        let app = Router::new()
            .route("/", post(fail_first))
            .with_state(Arc::clone(&hits));
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = strict_push_handler(IndexedEventsExecutor {
            count: 10,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-skip", "ctx-t-skip").await;
        let mut config = push_config("t-skip");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-skip"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        assert!(events.last().is_some_and(Result::is_err), "{events:?}");

        // Give a queue that was not abandoned time to drain.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "pushes queued behind the failure were still delivered"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// One task with 8 configs on a webhook that answers after 1 s, and 70
    /// events a millisecond apart. The first event is in flight (4 requests
    /// started, the other 4 waiting for a free slot of the task) when the
    /// queue is full and one event is dropped and reported. The report
    /// abandons the execution, so the 4 requests of the first event that had
    /// not started are skipped: 4 requests in all, not 8. The stream ends with
    /// the queue-full error.
    #[tokio::test]
    async fn a_queue_full_report_stops_the_requests_of_the_event_in_flight() {
        install_crypto_provider();
        async fn slow_count(State(hits): State<Arc<AtomicI32>>) -> StatusCode {
            hits.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
            StatusCode::ACCEPTED
        }
        let hits = Arc::new(AtomicI32::new(0));
        let app = Router::new()
            .route("/", post(slow_count))
            .with_state(Arc::clone(&hits));
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = strict_push_handler(IndexedEventsExecutor {
            count: 70,
            gap: Duration::from_millis(1),
        });
        let params = ServiceParams::new();
        seed_task(&handler, "t-inflight", "ctx-t-inflight").await;
        for index in 0..8 {
            let mut config = push_config("t-inflight");
            config.id = Some(format!("cfg-{index}"));
            config.url = url.clone();
            handler.create_push_config(&params, config).await.unwrap();
        }

        let events = handler
            .send_streaming_message(&params, streaming_request("t-inflight"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let error = events
            .last()
            .and_then(|event| event.as_ref().err())
            .unwrap_or_else(|| {
                panic!(
                    "the stream did not end with an error: {} events",
                    events.len()
                )
            });
        assert!(
            error.message.contains("push notification queue full"),
            "{error:?}"
        );

        // Time for the second group of 4 requests, if it were started.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            4,
            "requests of the event in flight were started after the execution was abandoned"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// One config fails at once and its sibling answers after 1.5 s. The
    /// cancellation's own push stops at its first failed request, so the
    /// cancellation returns that error without waiting for the sibling.
    #[tokio::test]
    async fn cancel_returns_the_first_failed_request_of_its_own_push() {
        install_crypto_provider();
        async fn reject() -> StatusCode {
            StatusCode::BAD_REQUEST
        }
        async fn slow() -> StatusCode {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            StatusCode::ACCEPTED
        }
        let (url, shutdown_tx, server) = serve(
            Router::new()
                .route("/fail", post(reject))
                .route("/slow", post(slow)),
        )
        .await;
        let handler = strict_push_handler(PushEventExecutor);
        let params = ServiceParams::new();
        seed_task(&handler, "t-cstop", "ctx-t-cstop").await;
        for (id, path) in [("a-slow", "slow"), ("b-fail", "fail")] {
            let mut config = push_config("t-cstop");
            config.id = Some(id.into());
            config.url = format!("{url}{path}");
            handler.create_push_config(&params, config).await.unwrap();
        }

        let started = std::time::Instant::now();
        let result = handler
            .cancel_task(
                &params,
                CancelTaskRequest {
                    id: "t-cstop".into(),
                    metadata: None,
                    tenant: None,
                },
            )
            .await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "{result:?}");
        assert!(
            elapsed < Duration::from_millis(800),
            "the cancellation waited for the sibling request: {elapsed:?}"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// Five pushes of a running execution are queued ahead of a cancellation,
    /// on a webhook that answers after 400 ms; the first request fails, which
    /// the execution records. The four pushes that the failure abandoned are
    /// skipped, so the cancellation waits for the first one and for its own
    /// (2 requests, not 6), and returns its own outcome, which is success:
    /// the error of the earlier push went to the execution.
    #[tokio::test]
    async fn cancel_skips_the_pushes_a_recorded_strict_failure_abandoned() {
        install_crypto_provider();
        async fn fail_first(State(hits): State<Arc<AtomicI32>>) -> StatusCode {
            tokio::time::sleep(Duration::from_millis(400)).await;
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::ACCEPTED
            }
        }
        let hits = Arc::new(AtomicI32::new(0));
        let app = Router::new()
            .route("/", post(fail_first))
            .with_state(Arc::clone(&hits));
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = strict_push_handler(PushEventExecutor);
        let params = ServiceParams::new();
        seed_task(&handler, "t-cabandon", "ctx-t-cabandon").await;
        let mut config = push_config("t-cabandon");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        // The running execution: it owns the abandon flag and the sink.
        let active = ActiveExecution::new(Task {
            id: "t-cabandon".into(),
            context_id: "ctx-t-cabandon".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        });
        let sink: PushErrorSink = {
            let active = Arc::clone(&active);
            Arc::new(move |error| active.record_push_failure(error))
        };
        let working = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: "t-cabandon".into(),
            context_id: "ctx-t-cabandon".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            metadata: None,
        });
        for _ in 0..5 {
            enqueue_push(
                &handler.push_dispatcher,
                "t-cabandon",
                handler.push_config_store.as_ref(),
                handler.push_sender.as_ref(),
                Some(&working),
                Some(Arc::clone(&sink)),
                Some(Arc::clone(&active.push_abandoned)),
                false,
            );
        }

        let started = std::time::Instant::now();
        let result = handler
            .cancel_task(
                &params,
                CancelTaskRequest {
                    id: "t-cabandon".into(),
                    metadata: None,
                    tenant: None,
                },
            )
            .await;
        let elapsed = started.elapsed();

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "pushes of the failed execution were not skipped"
        );
        assert!(
            elapsed < Duration::from_millis(1600),
            "the cancellation waited for the abandoned pushes: {elapsed:?}"
        );
        assert!(active.take_push_failure().is_some());

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// The in-memory store, listing a task's configs in the order of their
    /// ids instead of in hash order.
    struct SortedPushConfigStore(InMemoryPushConfigStore);

    #[async_trait]
    impl PushConfigStore for SortedPushConfigStore {
        async fn save(
            &self,
            config: TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            self.0.save(config).await
        }
        async fn get(
            &self,
            task_id: &str,
            config_id: &str,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            self.0.get(task_id, config_id).await
        }
        async fn list(&self, task_id: &str) -> Result<Vec<TaskPushNotificationConfig>, A2AError> {
            let mut configs = self.0.list(task_id).await?;
            configs.sort_by(|a, b| a.id.cmp(&b.id));
            Ok(configs)
        }
        async fn delete(&self, task_id: &str, config_id: &str) -> Result<(), A2AError> {
            self.0.delete(task_id, config_id).await
        }
        async fn delete_all(&self, task_id: &str) -> Result<(), A2AError> {
            self.0.delete_all(task_id).await
        }
    }

    /// 40 configs answer after 300 ms and one fails at once. A store that
    /// lists them in a fixed order puts the failing config last, the worst
    /// case: its request starts only when a slot frees up after
    /// floor(40 / 4) = 10 request times, it fails at once, and nothing is
    /// awaited after it, so the run ends within 11 request times (11 x
    /// 300 ms) plus 1500 ms of slack for a loaded host.
    #[tokio::test]
    async fn a_failure_behind_slow_successful_configs_is_known_within_the_documented_bound() {
        install_crypto_provider();
        async fn slow_ok() -> StatusCode {
            tokio::time::sleep(Duration::from_millis(300)).await;
            StatusCode::ACCEPTED
        }
        async fn reject() -> StatusCode {
            StatusCode::BAD_REQUEST
        }
        let (url, shutdown_tx, server) = serve(
            Router::new()
                .route("/ok", post(slow_ok))
                .route("/fail", post(reject)),
        )
        .await;
        let handler = DefaultRequestHandler::new(
            IndexedEventsExecutor {
                count: 0,
                gap: Duration::ZERO,
            },
            InMemoryTaskStore::new(),
        )
        .with_push_notifications(
            SortedPushConfigStore(InMemoryPushConfigStore::new()),
            crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                validate_urls: false,
                fail_on_error: true,
                ..Default::default()
            })),
        );
        let params = ServiceParams::new();
        seed_task(&handler, "t-behind", "ctx-t-behind").await;
        for index in 0..41 {
            let mut config = push_config("t-behind");
            config.id = Some(format!("cfg-{index:02}"));
            let path = if index == 40 { "fail" } else { "ok" };
            config.url = format!("{url}{path}");
            handler.create_push_config(&params, config).await.unwrap();
        }

        let started = std::time::Instant::now();
        let events = handler
            .send_streaming_message(&params, streaming_request("t-behind"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let elapsed = started.elapsed();

        eprintln!("failure behind 40 slow successful configs: {elapsed:?}");
        assert!(events.last().is_some_and(Result::is_err), "{events:?}");
        assert!(
            elapsed < Duration::from_millis(11 * 300 + 1500),
            "the failure was not known within the documented bound: {elapsed:?}"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    /// A failure recorded on the execution ends a wait on a push outcome that
    /// never completes, at once.
    #[tokio::test]
    async fn a_recorded_push_failure_wakes_a_pending_wait() {
        let active = ActiveExecution::new(Task {
            id: "t-wake".into(),
            context_id: "ctx-t-wake".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        });
        let (_never, outcome) = oneshot::channel::<Result<(), A2AError>>();
        let recorder = Arc::clone(&active);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            recorder.record_push_failure(A2AError::internal("push failed"));
        });

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            await_push_or_failure(&active, outcome),
        )
        .await
        .expect("the recorded failure did not wake the wait");
        assert!(result.is_err());
    }

    /// An error known before any request is sent fails the event
    /// synchronously in strict mode too: the first event (a working update)
    /// is not published, the stream starts with the error. Without the check
    /// the error would only surface at the terminal wait, after the working
    /// event.
    #[tokio::test]
    async fn strict_precheck_error_fails_the_event_synchronously() {
        install_crypto_provider();
        let handler = DefaultRequestHandler::new(
            IndexedEventsExecutor {
                count: 1,
                gap: Duration::ZERO,
            },
            InMemoryTaskStore::new(),
        )
        .with_push_notifications(
            InMemoryPushConfigStore::new(),
            crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                fail_on_error: true,
                ..Default::default()
            })),
        );
        let params = ServiceParams::new();
        seed_task(&handler, "t-spre", "ctx-t-spre").await;
        let mut config = push_config("t-spre");
        config.url = "http://169.254.169.254/hook".into();
        handler.create_push_config(&params, config).await.unwrap();

        let events = handler
            .send_streaming_message(&params, streaming_request("t-spre"))
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        let first_error = events
            .iter()
            .position(Result::is_err)
            .unwrap_or_else(|| panic!("the blocked URL was not reported: {events:?}"));
        assert!(
            events[first_error]
                .as_ref()
                .is_err_and(|error| error.message.contains("blocked host")),
            "{events:?}"
        );
        assert!(
            !events[..first_error]
                .iter()
                .any(|event| matches!(event, Ok(StreamResponse::StatusUpdate(_)))),
            "an event was published before the blocked URL was reported: {events:?}"
        );
    }

    /// A push URL on a blocked host fails a cancellation, with the flag off
    /// and with it on.
    #[tokio::test]
    async fn cancel_with_a_blocked_push_url_fails_in_both_modes() {
        install_crypto_provider();
        for fail_on_error in [false, true] {
            let task_id = format!("t-cpre-{fail_on_error}");
            let handler = DefaultRequestHandler::new(PushEventExecutor, InMemoryTaskStore::new())
                .with_push_notifications(
                    InMemoryPushConfigStore::new(),
                    crate::HttpPushSender::new(Some(crate::HttpPushSenderConfig {
                        fail_on_error,
                        ..Default::default()
                    })),
                );
            let params = ServiceParams::new();
            seed_task(&handler, &task_id, &format!("ctx-{task_id}")).await;
            let mut config = push_config(&task_id);
            config.url = "http://169.254.169.254/hook".into();
            handler.create_push_config(&params, config).await.unwrap();

            let result = handler
                .cancel_task(
                    &params,
                    CancelTaskRequest {
                        id: task_id.clone(),
                        metadata: None,
                        tenant: None,
                    },
                )
                .await;
            let error = result.expect_err("the blocked URL was not reported");
            assert!(
                error.message.contains("blocked host"),
                "fail_on_error={fail_on_error}: {error:?}"
            );
        }
    }

    /// With 8 busy tasks of 4 slow webhooks each the shared pool of 32 is
    /// full, so a newcomer waits for a slot: about one request time (the
    /// documented `ceil(4 * T / 32)` for `T = 8`), not the queue time.
    #[tokio::test]
    async fn many_slow_tasks_delay_a_newcomer_by_about_one_request_time() {
        install_crypto_provider();
        let slow = Router::new()
            .route("/", post(slow_push))
            .with_state(Duration::from_secs(1));
        let (slow_url, _slow_tx, _slow_srv) = serve(slow).await;
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let fast = Router::new()
            .route("/", post(indexed_push))
            .with_state(sender);
        let (fast_url, fast_tx, fast_srv) = serve(fast).await;
        let handler = local_push_handler(IndexedEventsExecutor {
            count: 1,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        for task in 0..8 {
            let id = format!("t-busy-{task}");
            seed_task(&handler, &id, &format!("ctx-{id}")).await;
            for index in 0..4 {
                let mut config = push_config(&id);
                config.id = Some(format!("cfg-{index}"));
                config.url = slow_url.clone();
                handler.create_push_config(&params, config).await.unwrap();
            }
            let mut events = handler
                .send_streaming_message(&params, streaming_request(&id))
                .await
                .unwrap();
            while let Some(event) = events.next().await {
                event.unwrap();
            }
        }
        seed_task(&handler, "t-new", "ctx-t-new").await;
        let mut config = push_config("t-new");
        config.url = fast_url;
        handler.create_push_config(&params, config).await.unwrap();

        let started = std::time::Instant::now();
        let mut events = handler
            .send_streaming_message(&params, streaming_request("t-new"))
            .await
            .unwrap();
        while let Some(event) = events.next().await {
            event.unwrap();
        }
        timeout(Duration::from_secs(30), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let elapsed = started.elapsed();
        eprintln!("newcomer first push after 8 slow tasks: {elapsed:?}");
        fast_tx.send(()).unwrap();
        fast_srv.await.unwrap();
        assert!(
            elapsed < Duration::from_millis(2500),
            "a newcomer waited longer than about one request time: {elapsed:?}"
        );
    }

    /// Latency of the first push of an unrelated task while `busy_tasks`
    /// tasks with `configs_per_task` webhook configs each are busy. One task
    /// can use at most 4 of the 32 shared slots, so 8 tasks of 4 configs are
    /// needed to fill the pool.
    async fn victim_first_push_latency(
        slow_url: String,
        busy_tasks: usize,
        configs_per_task: usize,
    ) -> Duration {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let fast = Router::new()
            .route("/", post(indexed_push))
            .with_state(sender);
        let (fast_url, fast_tx, fast_srv) = serve(fast).await;
        let handler = local_push_handler(IndexedEventsExecutor {
            count: 1,
            gap: Duration::ZERO,
        });
        let params = ServiceParams::new();
        for task in 0..busy_tasks {
            let id = format!("t-busy-{task}");
            seed_task(&handler, &id, &format!("ctx-{id}")).await;
            for index in 0..configs_per_task {
                let mut config = push_config(&id);
                config.id = Some(format!("cfg-{index}"));
                config.url = slow_url.clone();
                handler.create_push_config(&params, config).await.unwrap();
            }
        }
        seed_task(&handler, "t-victim", "ctx-t-victim").await;
        let mut config = push_config("t-victim");
        config.url = fast_url;
        handler.create_push_config(&params, config).await.unwrap();

        // Every busy task has queued its pushes before the victim starts.
        for task in 0..busy_tasks {
            let mut events = handler
                .send_streaming_message(&params, streaming_request(&format!("t-busy-{task}")))
                .await
                .unwrap();
            while let Some(event) = events.next().await {
                event.unwrap();
            }
        }
        let started = std::time::Instant::now();
        let mut events = handler
            .send_streaming_message(&params, streaming_request("t-victim"))
            .await
            .unwrap();
        while let Some(event) = events.next().await {
            event.unwrap();
        }
        timeout(Duration::from_secs(60), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let elapsed = started.elapsed();
        fast_tx.send(()).unwrap();
        fast_srv.await.unwrap();
        elapsed
    }

    /// Webhook that asks the sender to come back in two seconds.
    async fn retry_later_push() -> (StatusCode, [(&'static str, &'static str); 1]) {
        (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "2")])
    }

    #[tokio::test]
    async fn retry_waits_of_one_task_do_not_starve_other_tasks() {
        install_crypto_provider();
        let (slow_url, slow_tx, slow_srv) =
            serve(Router::new().route("/", post(retry_later_push))).await;
        // 10 tasks x 5 configs retry for 2 s each (50 waits, more than the 32
        // shared slots): a permit held across the wait would fill the pool
        // and delay the other task.
        let elapsed = victim_first_push_latency(slow_url, 10, 5).await;
        slow_tx.send(()).unwrap();
        drop(slow_srv);
        assert!(
            elapsed < Duration::from_secs(1),
            "a retry sleep held a delivery slot: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn slow_webhooks_of_one_task_do_not_starve_other_tasks() {
        install_crypto_provider();
        let slow = Router::new()
            .route("/", post(slow_push))
            .with_state(Duration::from_secs(3));
        let (slow_url, slow_tx, slow_srv) = serve(slow).await;
        let elapsed = victim_first_push_latency(slow_url, 1, 40).await;
        slow_tx.send(()).unwrap();
        drop(slow_srv);
        assert!(
            elapsed < Duration::from_secs(1),
            "an unrelated task's push waited for another task's webhooks: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn cancel_does_not_wait_for_a_slow_webhook() {
        install_crypto_provider();
        let app = Router::new()
            .route("/", post(slow_push))
            .with_state(Duration::from_secs(2));
        let (url, shutdown_tx, server) = serve(app).await;
        let handler = local_push_handler(PushEventExecutor);
        let params = ServiceParams::new();
        seed_task(&handler, "t-cancel", "ctx-t-cancel").await;
        let mut config = push_config("t-cancel");
        config.url = url;
        handler.create_push_config(&params, config).await.unwrap();

        let started = std::time::Instant::now();
        let task = handler
            .cancel_task(
                &params,
                CancelTaskRequest {
                    id: "t-cancel".into(),
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(task.status.state, TaskState::Canceled);
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "cancel waited for the webhook: {:?}",
            started.elapsed()
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_message_creates_task() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: make_message(),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let result = handler.send_message(&params, req).await.unwrap();
        match result {
            SendMessageResponse::Task(task) => {
                assert_eq!(task.status.state, TaskState::Completed);
            }
            _ => panic!("expected Task response"),
        }
    }

    #[tokio::test]
    async fn test_send_streaming_message() {
        use futures::StreamExt;
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: make_message(),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let mut stream = handler.send_streaming_message(&params, req).await.unwrap();
        let event = stream.next().await.unwrap().unwrap();
        assert!(matches!(event, StreamResponse::Task(_)));
    }

    /// DM-SERIAL-001: `save_task`'s backfill only covers what gets persisted
    /// -- a live subscriber receives the broadcast event directly, never a
    /// reload from the store, so the timestamp must also be backfilled on
    /// the event itself before it is published.
    #[tokio::test]
    async fn test_streamed_task_event_has_a_backfilled_timestamp() {
        use futures::StreamExt;
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: make_message(),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let mut stream = handler.send_streaming_message(&params, req).await.unwrap();
        let event = stream.next().await.unwrap().unwrap();
        match event {
            StreamResponse::Task(task) => assert!(
                task.status.timestamp.is_some(),
                "a live-streamed task event must carry a backfilled timestamp"
            ),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    /// `ArtifactUpdate` and `Message` carry no status of their own, so the
    /// backfill must leave them alone rather than panic on the missing arm.
    #[test]
    fn test_backfill_status_timestamp_ignores_events_without_a_status() {
        let mut artifact_update = StreamResponse::ArtifactUpdate(TaskArtifactUpdateEvent {
            task_id: "t1".into(),
            context_id: "c1".into(),
            artifact: Artifact {
                artifact_id: "a1".into(),
                name: None,
                description: None,
                parts: vec![Part::text("payload")],
                metadata: None,
                extensions: None,
            },
            append: None,
            last_chunk: None,
            metadata: None,
        });
        let before = artifact_update.clone();
        backfill_status_timestamp(&mut artifact_update);
        assert_eq!(artifact_update, before);

        let mut message = StreamResponse::Message(make_message());
        let before = message.clone();
        backfill_status_timestamp(&mut message);
        assert_eq!(message, before);
    }

    /// DM-SERIAL-001: a status update whose status omits a timestamp must be
    /// backfilled before the task is persisted, so a returned task never
    /// carries a timestamp-less status.
    #[tokio::test]
    async fn test_status_update_backfills_missing_timestamp() {
        let store = InMemoryTaskStore::new();
        store
            .create(Task {
                id: "t-backfill".into(),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: Some(chrono::Utc::now()),
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
            .await
            .unwrap();

        let updated = apply_event_to_task(
            &store,
            None,
            &StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: "t-backfill".into(),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            }),
        )
        .await
        .unwrap()
        .expect("status update yields a task");

        assert_eq!(updated.status.state, TaskState::Working);
        assert!(
            updated.status.timestamp.is_some(),
            "missing status timestamp must be backfilled"
        );
    }

    /// A timestamp supplied by the executor is authoritative and must be kept
    /// verbatim, not overwritten by the backfill.
    #[tokio::test]
    async fn test_status_update_preserves_supplied_timestamp() {
        let store = InMemoryTaskStore::new();
        store
            .create(Task {
                id: "t-preserve".into(),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
            .await
            .unwrap();

        let supplied = chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let updated = apply_event_to_task(
            &store,
            None,
            &StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: "t-preserve".into(),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: Some(supplied),
                },
                metadata: None,
            }),
        )
        .await
        .unwrap()
        .expect("status update yields a task");

        assert_eq!(updated.status.timestamp, Some(supplied));
    }

    /// The task-snapshot arm persists through the same `save_task` chokepoint,
    /// so an executor `Task` event whose status omits a timestamp must also be
    /// backfilled (DM-SERIAL-001).
    #[tokio::test]
    async fn test_task_snapshot_backfills_missing_timestamp() {
        let store = InMemoryTaskStore::new();

        let returned = apply_event_to_task(
            &store,
            None,
            &StreamResponse::Task(Task {
                id: "t-snapshot".into(),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            }),
        )
        .await
        .unwrap()
        .expect("task event yields a task");

        assert!(
            returned.status.timestamp.is_some(),
            "missing status timestamp must be backfilled on the task-snapshot path"
        );
        let persisted = store.get("t-snapshot").await.unwrap().unwrap();
        assert!(
            persisted.status.timestamp.is_some(),
            "the persisted task must carry a timestamp"
        );
    }

    /// A timestamp already present on a task snapshot is authoritative and
    /// must survive the persistence chokepoint unchanged.
    #[tokio::test]
    async fn test_task_snapshot_preserves_supplied_timestamp() {
        let store = InMemoryTaskStore::new();

        let supplied = chrono::DateTime::parse_from_rfc3339("2021-06-07T08:09:10Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let returned = apply_event_to_task(
            &store,
            None,
            &StreamResponse::Task(Task {
                id: "t-snapshot-kept".into(),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: Some(supplied),
                },
                artifacts: None,
                history: None,
                metadata: None,
            }),
        )
        .await
        .unwrap()
        .expect("task event yields a task");

        assert_eq!(returned.status.timestamp, Some(supplied));
        let persisted = store.get("t-snapshot-kept").await.unwrap().unwrap();
        assert_eq!(persisted.status.timestamp, Some(supplied));
    }

    #[tokio::test]
    async fn test_stream_disconnect_preserves_execution_for_resubscription() {
        use futures::StreamExt;

        let (handler, release) = make_resumable_handler();
        let params = ServiceParams::new();
        let mut message = make_message();
        message.task_id = Some("t-disconnect".into());
        message.context_id = Some("c-disconnect".into());
        seed_task(&handler, "t-disconnect", "c-disconnect").await;

        let mut stream = handler
            .send_streaming_message(
                &params,
                SendMessageRequest {
                    message,
                    configuration: None,
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        let initial = stream.next().await.unwrap().unwrap();
        match initial {
            StreamResponse::Task(task) => assert_eq!(task.status.state, TaskState::Working),
            _ => panic!("expected initial working task"),
        }
        drop(stream);

        let mut resumed = handler
            .subscribe_to_task(
                &params,
                SubscribeToTaskRequest {
                    id: "t-disconnect".into(),
                    tenant: None,
                },
            )
            .await
            .unwrap();

        let snapshot = resumed.next().await.unwrap().unwrap();
        match snapshot {
            StreamResponse::Task(task) => assert_eq!(task.status.state, TaskState::Working),
            _ => panic!("expected working task snapshot"),
        }

        release.notify_waiters();

        let terminal = resumed.next().await.unwrap().unwrap();
        match terminal {
            StreamResponse::Task(task) => {
                assert_eq!(task.status.state, TaskState::Completed)
            }
            _ => panic!("expected terminal task"),
        }
        assert!(resumed.next().await.is_none());
    }

    #[tokio::test]
    async fn test_active_execution_keeps_snapshot_without_subscribers() {
        let task = Task {
            id: "t-buffering".into(),
            context_id: "c-buffering".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let active = ActiveExecution::new(task.clone());

        let event = StreamResponse::Task(task.clone());
        active.publish(Ok(&event), Some(task)).await;

        let (mut receiver, snapshot_task, sequence) = active.resubscribe().await;
        assert_eq!(snapshot_task.unwrap().id, "t-buffering");
        assert_eq!(sequence, 1);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_active_execution_publishes_errors_to_subscribers() {
        let task = Task {
            id: "t-buffering-error".into(),
            context_id: "c-buffering-error".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let active = ActiveExecution::new(task);
        let mut receiver = active.subscribe();
        let error = A2AError::internal("execution failed");

        active.publish(Err(&error), None).await;

        let event = receiver.recv().await.unwrap();
        assert_eq!(event.sequence, 1);
        assert_eq!(event.result.unwrap_err().code, error.code);
    }

    #[tokio::test]
    async fn test_active_execution_drops_errors_without_subscribers() {
        let task = Task {
            id: "t-error-no-sub".into(),
            context_id: "c-error-no-sub".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let active = ActiveExecution::new(task.clone());
        let error = A2AError::internal("execution failed");

        // Publish error without any subscribers
        active.publish(Err(&error), Some(task.clone())).await;

        // Resubscribe to verify snapshot was updated but no event was buffered
        let (mut receiver, snapshot_task, sequence) = active.resubscribe().await;
        assert_eq!(snapshot_task.unwrap().id, "t-error-no-sub");
        assert_eq!(sequence, 1);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_active_execution_publishes_events_with_snapshot_updates() {
        let initial_task = Task {
            id: "t-snapshot-update".into(),
            context_id: "c-snapshot-update".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let active = ActiveExecution::new(initial_task.clone());
        let mut receiver = active.subscribe();

        let updated_task = Task {
            id: "t-snapshot-update".into(),
            context_id: "c-snapshot-update".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };

        let event = StreamResponse::Task(updated_task.clone());
        active.publish(Ok(&event), Some(updated_task.clone())).await;

        // Verify event was published to subscriber
        let published = receiver.recv().await.unwrap();
        assert_eq!(published.sequence, 1);
        match published.result {
            Ok(StreamResponse::Task(task)) => {
                assert_eq!(task.id, "t-snapshot-update");
            }
            _ => panic!("expected Ok(Task) event"),
        }

        // Verify snapshot was updated
        let (_, snapshot_task, sequence) = active.resubscribe().await;
        assert_eq!(snapshot_task.unwrap().id, "t-snapshot-update");
        assert_eq!(sequence, 1);
    }

    #[tokio::test]
    async fn test_active_execution_broadcasts_to_multiple_subscribers() {
        let task = Task {
            id: "t-multi-sub".into(),
            context_id: "c-multi-sub".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let active = ActiveExecution::new(task.clone());

        // Create two subscribers
        let mut sub1 = active.subscribe();
        let mut sub2 = active.subscribe();

        let event = StreamResponse::Task(task);
        active.publish(Ok(&event), None).await;

        // Both subscribers should receive the same event
        let evt1 = sub1.recv().await.unwrap();
        let evt2 = sub2.recv().await.unwrap();

        assert_eq!(evt1.sequence, 1);
        assert_eq!(evt2.sequence, 1);
        assert!(matches!(evt1.result, Ok(StreamResponse::Task(_))));
        assert!(matches!(evt2.result, Ok(StreamResponse::Task(_))));
    }

    #[tokio::test]
    async fn test_get_task_not_found() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = GetTaskRequest {
            id: "nonexistent".into(),
            history_length: None,
            tenant: None,
        };
        let result = handler.get_task(&params, req).await;
        assert!(result.is_err());
    }

    // A2A §3.4.2 / §3.4.3: taskId and contextId rules on send_message (#248).

    fn send_req(task_id: Option<&str>, context_id: Option<&str>) -> SendMessageRequest {
        let mut msg = make_message();
        msg.task_id = task_id.map(Into::into);
        msg.context_id = context_id.map(Into::into);
        SendMessageRequest {
            message: msg,
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    #[tokio::test]
    async fn test_send_message_rejects_unsupported_content_type() {
        install_crypto_provider();
        let handler = make_handler().with_default_input_modes(vec!["text/plain".into()]);
        let mut req = send_req(None, None);
        req.message.parts = vec![
            Part::data(serde_json::json!({"value": "unsupported"}))
                .with_media_type("application/x-unsupported-type-12345"),
        ];
        let err = handler
            .send_message(&ServiceParams::new(), req)
            .await
            .expect_err("an undeclared content type must be rejected");
        assert_eq!(err.code, error_code::CONTENT_TYPE_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn test_send_message_accepts_a_declared_content_type() {
        install_crypto_provider();
        let handler = make_handler().with_default_input_modes(vec!["text/plain".into()]);
        let mut req = send_req(None, None);
        req.message.parts = vec![Part::text("hello").with_media_type("text/plain")];
        handler
            .send_message(&ServiceParams::new(), req)
            .await
            .expect("a declared content type must be accepted");
    }

    #[tokio::test]
    async fn test_send_message_allows_any_content_type_when_none_declared() {
        install_crypto_provider();
        let handler = make_handler();
        let mut req = send_req(None, None);
        req.message.parts = vec![
            Part::data(serde_json::json!({"value": "x"})).with_media_type("application/x-anything"),
        ];
        handler
            .send_message(&ServiceParams::new(), req)
            .await
            .expect("no declared modes means no restriction");
    }

    #[tokio::test]
    async fn test_send_message_unknown_task_id_is_not_found() {
        install_crypto_provider();
        let handler = make_handler();
        // §3.4.2: a client-provided taskId MUST reference an existing task, and
        // MUST NOT create one. Silently minting a task here is what let a
        // mistyped or replayed id start a fresh conversation.
        let err = handler
            .send_message(&ServiceParams::new(), send_req(Some("t-absent"), None))
            .await
            .expect_err("an unknown taskId must not create a task");
        assert_eq!(err.code, error_code::TASK_NOT_FOUND);
        assert!(
            handler.task_store.get("t-absent").await.unwrap().is_none(),
            "the rejected id must not have been created"
        );
    }

    #[tokio::test]
    async fn test_send_message_to_terminal_task_is_rejected() {
        install_crypto_provider();
        let handler = make_handler();
        handler
            .task_store
            .create(Task {
                id: "t-done".into(),
                context_id: "c-done".into(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
            .await
            .unwrap();
        let err = handler
            .send_message(&ServiceParams::new(), send_req(Some("t-done"), None))
            .await
            .expect_err("a follow-up to a terminal task must not be accepted");
        assert_eq!(err.code, error_code::UNSUPPORTED_OPERATION);
    }

    #[tokio::test]
    async fn test_send_message_mismatched_context_id_is_rejected() {
        install_crypto_provider();
        let handler = make_handler();
        seed_task(&handler, "t-ctx", "c-real").await;
        // §3.4.3: previously the stored contextId silently won, so a client
        // addressing the wrong conversation was never told.
        let err = handler
            .send_message(
                &ServiceParams::new(),
                send_req(Some("t-ctx"), Some("c-wrong")),
            )
            .await
            .expect_err("a mismatching contextId must be rejected");
        assert_eq!(err.code, error_code::INVALID_PARAMS);
        assert!(
            err.message.contains("c-wrong"),
            "error names the bad id: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn test_send_message_matching_context_id_is_accepted() {
        install_crypto_provider();
        let handler = make_handler();
        seed_task(&handler, "t-ok", "c-ok").await;
        handler
            .send_message(&ServiceParams::new(), send_req(Some("t-ok"), Some("c-ok")))
            .await
            .expect("a matching pair must be accepted");
    }

    #[tokio::test]
    async fn test_send_message_accumulates_history_across_turns() {
        // ACTS CORE-HIST-005/006: a multi-turn conversation's history must
        // include every turn's message, not just the one that created the
        // task. MultiTurnExecutor only ever emits a StatusUpdate, so this
        // exercises prepare_task_for_execution's continuation path exactly
        // as a real executor (which never touches history itself) does.
        install_crypto_provider();
        let handler = DefaultRequestHandler::new(MultiTurnExecutor, InMemoryTaskStore::new());

        let mut turn1 = make_message();
        turn1.parts = vec![Part::text("turn one")];
        let resp1 = handler
            .send_message(
                &ServiceParams::new(),
                SendMessageRequest {
                    message: turn1,
                    configuration: None,
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        let task_id = match resp1 {
            SendMessageResponse::Task(t) => t.id,
            SendMessageResponse::Message(_) => panic!("expected a task"),
        };

        for text in ["turn two", "done"] {
            let mut turn = make_message();
            turn.task_id = Some(task_id.clone());
            turn.parts = vec![Part::text(text)];
            handler
                .send_message(
                    &ServiceParams::new(),
                    SendMessageRequest {
                        message: turn,
                        configuration: None,
                        metadata: None,
                        tenant: None,
                    },
                )
                .await
                .unwrap();
        }

        let task = handler.task_store.get(&task_id).await.unwrap().unwrap();
        let history = task.history.expect("history must accumulate across turns");
        let texts: Vec<_> = history.iter().map(|m| m.text()).collect();
        assert_eq!(
            texts,
            vec![Some("turn one"), Some("turn two"), Some("done")]
        );
    }

    #[tokio::test]
    async fn test_send_message_applies_configuration_history_length_to_its_own_response() {
        // ACTS CORE-HIST-003: configuration.historyLength must govern
        // SendMessage's own inline task the same way history_length governs
        // a later GetTask, rather than always including the just-sent
        // message regardless of what was asked for.
        install_crypto_provider();
        let handler = DefaultRequestHandler::new(MultiTurnExecutor, InMemoryTaskStore::new());
        let mut message = make_message();
        message.parts = vec![Part::text("done")];
        let resp = handler
            .send_message(
                &ServiceParams::new(),
                SendMessageRequest {
                    message,
                    configuration: Some(SendMessageConfiguration {
                        accepted_output_modes: None,
                        task_push_notification_config: None,
                        history_length: Some(0),
                        return_immediately: None,
                    }),
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        let task = match resp {
            SendMessageResponse::Task(t) => t,
            SendMessageResponse::Message(_) => panic!("expected a task"),
        };
        assert!(
            task.history.is_none_or(|h| h.is_empty()),
            "historyLength=0 must clear history on SendMessage's own response"
        );
    }

    #[tokio::test]
    async fn test_send_message_infers_context_id_from_the_task() {
        install_crypto_provider();
        let handler = make_handler();
        seed_task(&handler, "t-infer", "c-infer").await;
        // §3.4.3: contextId MUST be inferred when only taskId is given.
        handler
            .send_message(&ServiceParams::new(), send_req(Some("t-infer"), None))
            .await
            .unwrap();
        let task = handler.task_store.get("t-infer").await.unwrap().unwrap();
        assert_eq!(task.context_id, "c-infer");
    }

    #[tokio::test]
    async fn test_send_message_without_task_id_still_creates_one() {
        install_crypto_provider();
        let handler = make_handler();
        // The server generates the id. A contextId alone is allowed and starts
        // a new task within that conversation.
        let resp = handler
            .send_message(&ServiceParams::new(), send_req(None, Some("c-new")))
            .await
            .expect("a message with no taskId must still create a task");
        let _ = resp;
        let listed = handler
            .task_store
            .list(&ListTasksRequest {
                context_id: Some("c-new".into()),
                status: None,
                page_size: None,
                page_token: None,
                history_length: None,
                include_artifacts: None,
                status_timestamp_after: None,
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(listed.tasks.len(), 1);
        assert_eq!(listed.tasks[0].context_id, "c-new");
    }

    #[tokio::test]
    async fn test_get_task_after_send() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let mut msg = make_message();
        msg.task_id = Some("t1".into());
        msg.context_id = Some("c1".into());
        seed_task(&handler, "t1", "c1").await;
        let req = SendMessageRequest {
            message: msg,
            configuration: None,
            metadata: None,
            tenant: None,
        };
        handler.send_message(&params, req).await.unwrap();
        let task = handler
            .get_task(
                &params,
                GetTaskRequest {
                    id: "t1".into(),
                    history_length: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(task.id, "t1");
    }

    #[tokio::test]
    async fn test_list_tasks() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = ListTasksRequest {
            context_id: None,
            status: None,
            page_size: None,
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: None,
            tenant: None,
        };
        let resp = handler.list_tasks(&params, req).await.unwrap();
        assert!(resp.tasks.is_empty());
    }

    #[tokio::test]
    async fn test_cancel_task_not_found() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = CancelTaskRequest {
            id: "nonexistent".into(),
            metadata: None,
            tenant: None,
        };
        let result = handler.cancel_task(&params, req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cancel_task_working() {
        let handler = make_handler();
        let params = ServiceParams::new();
        // First create a task via the store directly
        let task = Task {
            id: "t2".into(),
            context_id: "c2".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        handler.task_store.create(task).await.unwrap();
        let req = CancelTaskRequest {
            id: "t2".into(),
            metadata: None,
            tenant: None,
        };
        let result = handler.cancel_task(&params, req).await.unwrap();
        assert_eq!(result.status.state, TaskState::Canceled);
    }

    #[tokio::test]
    async fn test_cancel_task_concurrent_both_succeed_idempotently() {
        let handler = Arc::new(make_handler());
        let params = ServiceParams::new();
        let task = Task {
            id: "t-race".into(),
            context_id: "c-race".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        handler.task_store.create(task).await.unwrap();

        let handlers = vec![Arc::clone(&handler), Arc::clone(&handler)];
        let mut results = Vec::new();
        for handler in handlers {
            let params = params.clone();
            let req = CancelTaskRequest {
                id: "t-race".into(),
                metadata: None,
                tenant: None,
            };
            results.push(tokio::spawn(async move {
                handler.cancel_task(&params, req).await
            }));
        }
        for result in results {
            let task = result.await.unwrap().unwrap();
            assert_eq!(task.status.state, TaskState::Canceled);
        }
    }

    #[tokio::test]
    async fn test_cancel_task_already_completed() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let task = Task {
            id: "t3".into(),
            context_id: "c3".into(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        handler.task_store.create(task).await.unwrap();
        let req = CancelTaskRequest {
            id: "t3".into(),
            metadata: None,
            tenant: None,
        };
        let result = handler.cancel_task(&params, req).await;
        match result {
            Ok(_) => panic!("expected cancel of COMPLETED to fail"),
            Err(error) => assert_eq!(error.code, error_code::TASK_NOT_CANCELABLE),
        }
    }

    #[tokio::test]
    async fn test_cancel_task_already_canceled_is_idempotent() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let task = Task {
            id: "t-canceled".into(),
            context_id: "c-canceled".into(),
            status: TaskStatus {
                state: TaskState::Canceled,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        handler.task_store.create(task).await.unwrap();
        let req = CancelTaskRequest {
            id: "t-canceled".into(),
            metadata: None,
            tenant: None,
        };
        let result = handler.cancel_task(&params, req).await.unwrap();
        assert_eq!(result.status.state, TaskState::Canceled);
    }

    #[tokio::test]
    async fn test_cancel_task_failed_and_rejected_are_not_cancelable() {
        let handler = make_handler();
        let params = ServiceParams::new();
        for (id, state) in [
            ("t-failed", TaskState::Failed),
            ("t-rejected", TaskState::Rejected),
        ] {
            handler
                .task_store
                .create(Task {
                    id: id.into(),
                    context_id: format!("c-{id}"),
                    status: TaskStatus {
                        state,
                        message: None,
                        timestamp: None,
                    },
                    artifacts: None,
                    history: None,
                    metadata: None,
                })
                .await
                .unwrap();
            let result = handler
                .cancel_task(
                    &params,
                    CancelTaskRequest {
                        id: id.into(),
                        metadata: None,
                        tenant: None,
                    },
                )
                .await;
            match result {
                Ok(_) => panic!("expected cancel of {id} to fail"),
                Err(error) => assert_eq!(error.code, error_code::TASK_NOT_CANCELABLE),
            }
        }
    }

    fn task_with_history(id: &str, context_id: &str, n: usize) -> Task {
        Task {
            id: id.into(),
            context_id: context_id.into(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: Some(
                (0..n)
                    .map(|i| Message::new(Role::User, vec![Part::text(format!("m{i}"))]))
                    .collect(),
            ),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_get_task_applies_history_length() {
        let handler = make_handler();
        let params = ServiceParams::new();
        handler
            .task_store
            .create(task_with_history("hist", "c", 3))
            .await
            .unwrap();

        let full = handler
            .get_task(
                &params,
                GetTaskRequest {
                    id: "hist".into(),
                    history_length: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(full.history.as_ref().unwrap().len(), 3);

        let last = handler
            .get_task(
                &params,
                GetTaskRequest {
                    id: "hist".into(),
                    history_length: Some(1),
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(last.history.as_ref().unwrap().len(), 1);

        for hl in [0, -1] {
            let empty = handler
                .get_task(
                    &params,
                    GetTaskRequest {
                        id: "hist".into(),
                        history_length: Some(hl),
                        tenant: None,
                    },
                )
                .await
                .unwrap();
            assert!(
                empty.history.as_ref().unwrap().is_empty(),
                "history_length={hl} must clear history"
            );
        }
    }

    fn reject_unauthenticated(
        _params: &ServiceParams,
        _task_id: Option<&str>,
    ) -> Result<(), A2AError> {
        Err(A2AError::invalid_request("authentication required"))
    }

    #[tokio::test]
    async fn test_authorizer_rejects_handler_methods() {
        let handler = DefaultRequestHandler::new(EchoExecutor, InMemoryTaskStore::new())
            .with_authorizer(reject_unauthenticated)
            .with_push_config_store(InMemoryPushConfigStore::new());
        let params = ServiceParams::new();

        assert!(
            handler
                .send_message(
                    &params,
                    SendMessageRequest {
                        message: make_message(),
                        configuration: None,
                        metadata: None,
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .get_task(
                    &params,
                    GetTaskRequest {
                        id: "t".into(),
                        history_length: None,
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .list_tasks(
                    &params,
                    ListTasksRequest {
                        context_id: None,
                        status: None,
                        page_size: None,
                        page_token: None,
                        history_length: None,
                        status_timestamp_after: None,
                        include_artifacts: None,
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .cancel_task(
                    &params,
                    CancelTaskRequest {
                        id: "t".into(),
                        metadata: None,
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .subscribe_to_task(
                    &params,
                    SubscribeToTaskRequest {
                        id: "t".into(),
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .create_push_config(
                    &params,
                    TaskPushNotificationConfig {
                        url: "https://example.com/push".into(),
                        id: None,
                        task_id: "t".into(),
                        token: None,
                        authentication: None,
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .get_push_config(
                    &params,
                    GetTaskPushNotificationConfigRequest {
                        task_id: "t".into(),
                        id: "cfg".into(),
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .list_push_configs(
                    &params,
                    ListTaskPushNotificationConfigsRequest {
                        task_id: "t".into(),
                        page_size: None,
                        page_token: None,
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .delete_push_config(
                    &params,
                    DeleteTaskPushNotificationConfigRequest {
                        task_id: "t".into(),
                        id: "cfg".into(),
                        tenant: None,
                    },
                )
                .await
                .is_err()
        );
        assert!(
            handler
                .get_extended_agent_card(&params, GetExtendedAgentCardRequest { tenant: None })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_subscribe_requires_active_execution() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let req = SubscribeToTaskRequest {
            id: "t1".into(),
            tenant: None,
        };
        let result = handler.subscribe_to_task(&params, req).await;
        match result {
            Ok(_) => panic!("expected subscribe_to_task to fail"),
            Err(error) => assert_eq!(error.code, error_code::TASK_NOT_FOUND),
        }
    }

    #[tokio::test]
    async fn test_subscribe_to_terminal_task_is_unsupported_not_not_found() {
        let handler = make_handler();
        handler
            .task_store
            .create(Task {
                id: "t-done".into(),
                context_id: "c-done".into(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
            .await
            .unwrap();
        let result = handler
            .subscribe_to_task(
                &ServiceParams::new(),
                SubscribeToTaskRequest {
                    id: "t-done".into(),
                    tenant: None,
                },
            )
            .await;
        match result {
            Ok(_) => panic!("expected subscribe_to_task to fail"),
            Err(error) => assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION),
        }
    }

    #[tokio::test]
    async fn test_send_message_return_immediately_allows_resubscribe() {
        use futures::StreamExt;

        let (handler, release) = make_resumable_handler();
        let params = ServiceParams::new();
        let mut message = make_message();
        message.task_id = Some("t-resume".into());
        message.context_id = Some("c-resume".into());
        seed_task(&handler, "t-resume", "c-resume").await;

        let response = handler
            .send_message(
                &params,
                SendMessageRequest {
                    message,
                    configuration: Some(SendMessageConfiguration {
                        accepted_output_modes: None,
                        task_push_notification_config: None,
                        history_length: None,
                        return_immediately: Some(true),
                    }),
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        match response {
            SendMessageResponse::Task(task) => {
                assert_eq!(task.status.state, TaskState::Working);
            }
            _ => panic!("expected Task response"),
        }

        let mut subscription = handler
            .subscribe_to_task(
                &params,
                SubscribeToTaskRequest {
                    id: "t-resume".into(),
                    tenant: None,
                },
            )
            .await
            .unwrap();

        let snapshot = subscription.next().await.unwrap().unwrap();
        match snapshot {
            StreamResponse::Task(task) => assert_eq!(task.status.state, TaskState::Working),
            _ => panic!("expected snapshot task"),
        }

        release.notify_waiters();

        let terminal = subscription.next().await.unwrap().unwrap();
        match terminal {
            StreamResponse::Task(task) => assert_eq!(task.status.state, TaskState::Completed),
            _ => panic!("expected terminal task"),
        }

        assert!(subscription.next().await.is_none());

        let result = handler
            .subscribe_to_task(
                &params,
                SubscribeToTaskRequest {
                    id: "t-resume".into(),
                    tenant: None,
                },
            )
            .await;
        match result {
            Ok(_) => panic!("expected subscribe_to_task to fail after completion"),
            Err(error) => assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION),
        }
    }

    #[tokio::test]
    async fn test_push_config_not_supported_without_store() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let result = handler
            .create_push_config(
                &params,
                TaskPushNotificationConfig {
                    task_id: "t1".into(),
                    url: "http://example.com".into(),
                    id: None,
                    token: None,
                    authentication: None,
                    tenant: None,
                },
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_push_configs_invalid_page_token_errors() {
        install_crypto_provider();
        let handler = make_handler_with_push_configs();
        let params = ServiceParams::new();
        handler
            .create_push_config(
                &params,
                TaskPushNotificationConfig {
                    task_id: "t1".into(),
                    url: "https://example.com/callback".into(),
                    id: Some("cfg-1".into()),
                    token: None,
                    authentication: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        let result = handler
            .list_push_configs(
                &params,
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: None,
                    page_token: Some("not-a-number".into()),
                    tenant: None,
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn test_list_tasks_page_size_cap_bounds_a_store_that_ignores_it() {
        install_crypto_provider();
        // A store that pays no attention to page_size. Clamping the request
        // does nothing here; only truncating the response bounds it.
        let handler = DefaultRequestHandler::new(
            EchoExecutor,
            PagingTaskStore::new(MAX_PAGE_SIZE * 3, false),
        );

        let resp = handler
            .list_tasks(
                &ServiceParams::new(),
                ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: Some(1_000_000),
                    page_token: None,
                    history_length: None,
                    include_artifacts: None,
                    status_timestamp_after: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.tasks.len(), MAX_PAGE_SIZE);
    }

    #[tokio::test]
    async fn test_paging_stores_delegate_everything_except_list() {
        install_crypto_provider();
        // The cap tests above are only measuring the handler if these two
        // doubles differ from the real stores in `list` and nowhere else.
        // Pin that, so a later edit cannot quietly make them lie.
        let tasks = PagingTaskStore::new(0, true);
        let task = Task {
            id: "t-delegated".into(),
            context_id: "c1".into(),
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        tasks.create(task.clone()).await.unwrap();
        assert_eq!(
            tasks
                .get("t-delegated")
                .await
                .unwrap()
                .map(|t| t.status.state),
            Some(TaskState::Submitted)
        );
        let mut done = task.clone();
        done.status.state = TaskState::Completed;
        tasks.update(done).await.unwrap();
        assert_eq!(
            tasks
                .get("t-delegated")
                .await
                .unwrap()
                .map(|t| t.status.state),
            Some(TaskState::Completed)
        );

        // begin_cancel has no default (#250), so this must reach
        // InMemoryTaskStore's atomic implementation -- and refuse a task that
        // is already terminal, as the trait documents.
        let mut cancelable = task.clone();
        cancelable.id = "t-cancelable".into();
        cancelable.status.state = TaskState::Working;
        tasks.create(cancelable).await.unwrap();
        assert_eq!(
            tasks
                .begin_cancel("t-cancelable")
                .await
                .unwrap()
                .status
                .state,
            TaskState::Canceled
        );
        assert_eq!(
            tasks.begin_cancel("t-delegated").await.unwrap_err().code,
            error_code::TASK_NOT_CANCELABLE
        );

        let configs = PagingPushConfigStore::new(0);
        configs
            .save(TaskPushNotificationConfig {
                task_id: "t1".into(),
                url: "https://example.com/callback".into(),
                id: Some("cfg-1".into()),
                token: None,
                authentication: None,
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(
            configs.get("t1", "cfg-1").await.unwrap().id.as_deref(),
            Some("cfg-1")
        );
        configs.delete("t1", "cfg-1").await.unwrap();
        assert!(configs.get("t1", "cfg-1").await.is_err());
        configs.delete_all("t1").await.unwrap();
    }

    #[tokio::test]
    async fn test_list_tasks_page_size_cap_bounds_a_store_that_honours_it() {
        install_crypto_provider();
        // The ordinary case: the store does what it is asked, so what it is
        // asked for has to be bounded. Without the clamp this store would
        // build a million tasks.
        let store = PagingTaskStore::new(MAX_PAGE_SIZE * 3, true);
        let seen = Arc::clone(&store.seen_page_size);
        let handler = DefaultRequestHandler::new(EchoExecutor, store);

        let resp = handler
            .list_tasks(
                &ServiceParams::new(),
                ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: Some(1_000_000),
                    page_token: None,
                    history_length: None,
                    include_artifacts: None,
                    status_timestamp_after: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.tasks.len(), MAX_PAGE_SIZE);
        // The point of the clamp: the store is never asked for the million.
        // Asserting only on the response would pass with no clamp at all,
        // because the response bound would hide it.
        assert_eq!(seen.load(Ordering::SeqCst), MAX_PAGE_SIZE as i32);
    }

    #[tokio::test]
    async fn test_list_tasks_truncation_keeps_the_store_continuation_token() {
        install_crypto_provider();
        // Truncating must not strand the remainder. The handler cannot
        // synthesise a token for a paging scheme it does not own, so the
        // store's own token has to survive untouched -- otherwise a caller
        // that lost 200 tasks has no way to ask for them.
        let handler = DefaultRequestHandler::new(
            EchoExecutor,
            PagingTaskStore::new(MAX_PAGE_SIZE * 3, false)
                .with_next_page_token("cursor-from-store"),
        );

        let resp = handler
            .list_tasks(
                &ServiceParams::new(),
                ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: None,
                    page_token: None,
                    history_length: None,
                    include_artifacts: None,
                    status_timestamp_after: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.tasks.len(), DEFAULT_PAGE_SIZE);
        assert_eq!(resp.next_page_token, "cursor-from-store");
    }

    #[tokio::test]
    async fn test_list_tasks_honours_a_page_size_under_the_cap() {
        install_crypto_provider();
        // The clamp is an upper bound, not a floor: a modest request must
        // reach the store unchanged.
        let store = PagingTaskStore::new(MAX_PAGE_SIZE * 3, true);
        let seen = Arc::clone(&store.seen_page_size);
        let handler = DefaultRequestHandler::new(EchoExecutor, store);

        let resp = handler
            .list_tasks(
                &ServiceParams::new(),
                ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: Some(7),
                    page_token: None,
                    history_length: None,
                    include_artifacts: None,
                    status_timestamp_after: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(seen.load(Ordering::SeqCst), 7);
        assert_eq!(resp.tasks.len(), 7);
    }

    #[tokio::test]
    async fn test_list_push_configs_page_size_cap_bounds_a_custom_store() {
        install_crypto_provider();
        // InMemoryPushConfigStore caps a task at 50 configs, below the page
        // cap of 100, so it can never reach the clamp. A store without that
        // limit can, and is what the clamp exists for.
        let handler = DefaultRequestHandler::new(EchoExecutor, InMemoryTaskStore::new())
            .with_push_config_store(PagingPushConfigStore::new(MAX_PAGE_SIZE * 3));

        let resp = handler
            .list_push_configs(
                &ServiceParams::new(),
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: Some(1_000_000),
                    page_token: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.configs.len(), MAX_PAGE_SIZE);
        // The remainder must stay reachable, or the cap silently truncates.
        assert_eq!(resp.next_page_token.as_deref(), Some("100"));
    }

    #[tokio::test]
    async fn test_list_push_configs_page_size_is_capped() {
        install_crypto_provider();
        let handler = make_handler_with_push_configs();
        let params = ServiceParams::new();
        // Keep the count below InMemoryPushConfigStore's per-task cap
        // (MAX_PUSH_CONFIGS_PER_TASK), which rejects the 51st config.
        for i in 0..40 {
            handler
                .create_push_config(
                    &params,
                    TaskPushNotificationConfig {
                        task_id: "t1".into(),
                        url: format!("https://example.com/callback/{i}"),
                        id: Some(format!("cfg-{i:03}")),
                        token: None,
                        authentication: None,
                        tenant: None,
                    },
                )
                .await
                .unwrap();
        }

        // Requesting a huge page size must not error and returns everything
        // available. This does NOT exercise the cap -- 40 < MAX_PAGE_SIZE, so
        // a capped and an uncapped implementation agree here. The cap itself
        // is pinned by test_list_push_configs_page_size_cap_bounds_a_custom_store,
        // which is the only route that can reach it.
        let resp = handler
            .list_push_configs(
                &params,
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: Some(1000),
                    page_token: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.configs.len(), 40);
    }

    #[tokio::test]
    async fn test_push_config_crud_with_store() {
        install_crypto_provider();
        let handler = make_handler_with_push_configs();
        let params = ServiceParams::new();

        let created = handler
            .create_push_config(
                &params,
                TaskPushNotificationConfig {
                    task_id: "t1".into(),
                    url: "https://example.com/first".into(),
                    id: Some("cfg-1".into()),
                    token: None,
                    authentication: None,
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(created.id.as_deref(), Some("cfg-1"));

        handler
            .create_push_config(
                &params,
                TaskPushNotificationConfig {
                    task_id: "t1".into(),
                    url: "https://example.com/second".into(),
                    id: Some("cfg-2".into()),
                    token: None,
                    authentication: None,
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();

        let fetched = handler
            .get_push_config(
                &params,
                GetTaskPushNotificationConfigRequest {
                    task_id: "t1".into(),
                    id: "cfg-1".into(),
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(fetched.url, "https://example.com/first");

        let first_page = handler
            .list_push_configs(
                &params,
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: Some(1),
                    page_token: Some("0".into()),
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(first_page.configs.len(), 1);
        assert_eq!(first_page.configs[0].id.as_deref(), Some("cfg-1"));
        assert_eq!(first_page.next_page_token.as_deref(), Some("1"));

        let default_page = handler
            .list_push_configs(
                &params,
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: Some(0),
                    page_token: None,
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(default_page.configs.len(), 2);
        assert!(default_page.next_page_token.is_none());

        handler
            .delete_push_config(
                &params,
                DeleteTaskPushNotificationConfigRequest {
                    task_id: "t1".into(),
                    id: "cfg-1".into(),
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();

        let remaining = handler
            .list_push_configs(
                &params,
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: None,
                    page_token: None,
                    tenant: Some("tenant-a".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(remaining.configs.len(), 1);
        assert_eq!(remaining.configs[0].id.as_deref(), Some("cfg-2"));
    }

    #[tokio::test]
    async fn test_send_message_request_push_config_delivers_webhooks() {
        install_crypto_provider();
        let (url, mut receiver, shutdown_tx, server) = start_push_webhook().await;
        let handler = make_push_delivery_handler();
        let params = ServiceParams::new();
        let mut message = make_message();
        message.task_id = Some("t-push-request".into());
        message.context_id = Some("c-push-request".into());
        seed_task(&handler, "t-push-request", "c-push-request").await;

        let response = handler
            .send_message(
                &params,
                SendMessageRequest {
                    message,
                    configuration: Some(SendMessageConfiguration {
                        accepted_output_modes: None,
                        task_push_notification_config: Some(TaskPushNotificationConfig {
                            task_id: String::new(),
                            url: url.clone(),
                            id: Some("cfg-request".into()),
                            token: Some("notify-token".into()),
                            authentication: Some(AuthenticationInfo {
                                scheme: "bearer".into(),
                                credentials: Some("secret-token".into()),
                            }),
                            tenant: None,
                        }),
                        history_length: None,
                        return_immediately: None,
                    }),
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        match response {
            SendMessageResponse::Task(task) => assert_eq!(task.status.state, TaskState::Completed),
            _ => panic!("expected Task response"),
        }

        let saved = handler
            .get_push_config(
                &params,
                GetTaskPushNotificationConfigRequest {
                    task_id: "t-push-request".into(),
                    id: "cfg-request".into(),
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(saved.url, url);

        let first = next_push(&mut receiver).await;
        assert_eq!(first.authorization.as_deref(), Some("Bearer secret-token"));
        assert_eq!(first.notification_token.as_deref(), Some("notify-token"));
        match first.event {
            StreamResponse::StatusUpdate(update) => {
                assert_eq!(update.task_id, "t-push-request");
                assert_eq!(update.status.state, TaskState::Working);
            }
            _ => panic!("expected status update push"),
        }

        let second = next_push(&mut receiver).await;
        assert_eq!(second.authorization.as_deref(), Some("Bearer secret-token"));
        assert_eq!(second.notification_token.as_deref(), Some("notify-token"));
        match second.event {
            StreamResponse::Task(task) => {
                assert_eq!(task.id, "t-push-request");
                assert_eq!(task.status.state, TaskState::Completed);
            }
            _ => panic!("expected final task push"),
        }

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_message_stored_push_config_delivers_webhooks() {
        install_crypto_provider();
        let (url, mut receiver, shutdown_tx, server) = start_push_webhook().await;
        let handler = make_push_delivery_handler();
        let params = ServiceParams::new();

        handler
            .create_push_config(
                &params,
                TaskPushNotificationConfig {
                    task_id: "t-push-stored".into(),
                    url: url.clone(),
                    id: Some("cfg-stored".into()),
                    token: Some("stored-token".into()),
                    authentication: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        let mut message = make_message();
        message.task_id = Some("t-push-stored".into());
        message.context_id = Some("c-push-stored".into());
        seed_task(&handler, "t-push-stored", "c-push-stored").await;
        let response = handler
            .send_message(
                &params,
                SendMessageRequest {
                    message,
                    configuration: None,
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();

        match response {
            SendMessageResponse::Task(task) => assert_eq!(task.status.state, TaskState::Completed),
            _ => panic!("expected Task response"),
        }

        let first = next_push(&mut receiver).await;
        assert_eq!(first.notification_token.as_deref(), Some("stored-token"));
        match first.event {
            StreamResponse::StatusUpdate(update) => {
                assert_eq!(update.task_id, "t-push-stored");
                assert_eq!(update.status.state, TaskState::Working);
            }
            _ => panic!("expected status update push"),
        }

        let second = next_push(&mut receiver).await;
        assert_eq!(second.notification_token.as_deref(), Some("stored-token"));
        match second.event {
            StreamResponse::Task(task) => {
                assert_eq!(task.id, "t-push-stored");
                assert_eq!(task.status.state, TaskState::Completed);
            }
            _ => panic!("expected final task push"),
        }

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_extended_agent_card_not_configured() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let result = handler
            .get_extended_agent_card(&params, GetExtendedAgentCardRequest { tenant: None })
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_with_capabilities() {
        let handler = make_handler().with_capabilities(AgentCapabilities {
            streaming: Some(true),
            push_notifications: None,
            extensions: None,
            extended_agent_card: None,
        });
        assert_eq!(handler.capabilities.streaming, Some(true));
    }

    #[test]
    fn test_with_push_config_store_enables_push_capability() {
        install_crypto_provider();
        let handler = make_handler_with_push_configs();
        assert_eq!(handler.capabilities.push_notifications, Some(true));
    }

    // §13.3 (#203): a capability the card does not declare is not served.

    fn caps(streaming: Option<bool>, push: Option<bool>) -> AgentCapabilities {
        AgentCapabilities {
            streaming,
            push_notifications: push,
            extensions: None,
            extended_agent_card: None,
        }
    }

    fn send_request() -> SendMessageRequest {
        SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("hi")]),
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    fn push_config(task_id: &str) -> TaskPushNotificationConfig {
        TaskPushNotificationConfig {
            task_id: task_id.into(),
            url: "https://example.com/callback".into(),
            id: Some("cfg-1".into()),
            token: None,
            authentication: None,
            tenant: None,
        }
    }

    #[tokio::test]
    async fn test_streaming_refused_when_the_card_declares_it_absent() {
        let handler = make_handler().with_capabilities(caps(Some(false), None));
        let params = ServiceParams::new();

        // The Ok arm is a BoxStream, which is not Debug, so match rather
        // than unwrap_err().
        match handler
            .send_streaming_message(&params, send_request())
            .await
        {
            Err(error) => assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION),
            Ok(_) => panic!("streaming must be refused when the card declares it absent"),
        }

        match handler
            .subscribe_to_task(
                &params,
                SubscribeToTaskRequest {
                    id: "t1".into(),
                    tenant: None,
                },
            )
            .await
        {
            Err(error) => assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION),
            Ok(_) => panic!("subscribe must be refused when the card declares it absent"),
        }
    }

    #[tokio::test]
    async fn test_push_refused_when_the_card_declares_it_absent() {
        // A store *is* configured; the card declaring `false` is what refuses.
        // Before #203 this combination served push regardless.
        let handler = make_handler_with_push_configs().with_capabilities(caps(None, Some(false)));
        let params = ServiceParams::new();

        let error = handler
            .create_push_config(&params, push_config("t1"))
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::PUSH_NOTIFICATION_NOT_SUPPORTED);

        let error = handler
            .list_push_configs(
                &params,
                ListTaskPushNotificationConfigsRequest {
                    task_id: "t1".into(),
                    page_size: None,
                    page_token: None,
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::PUSH_NOTIFICATION_NOT_SUPPORTED);
    }

    /// The regression guard. `AgentCapabilities::default()` leaves every field
    /// `None`, and most embedders never call `with_capabilities`; if `None`
    /// started meaning "refuse", all of them would break at once.
    #[tokio::test]
    async fn test_undeclared_capabilities_stay_permissive() {
        let handler = make_handler_with_push_configs();
        let params = ServiceParams::new();

        assert!(
            handler
                .send_streaming_message(&params, send_request())
                .await
                .is_ok(),
            "an undeclared capability must not be treated as refused"
        );
        assert!(
            handler
                .create_push_config(&params, push_config("t1"))
                .await
                .is_ok()
        );
    }

    /// Supplying a store defaults the capability to `true` but must not
    /// override an explicit `false`, so the outcome does not depend on which
    /// builder method was called last.
    #[tokio::test]
    async fn test_builder_order_does_not_change_the_declared_capability() {
        let params = ServiceParams::new();

        for handler in [
            make_handler()
                .with_capabilities(caps(None, Some(false)))
                .with_push_config_store(InMemoryPushConfigStore::new()),
            make_handler()
                .with_push_config_store(InMemoryPushConfigStore::new())
                .with_capabilities(caps(None, Some(false))),
        ] {
            let error = handler
                .create_push_config(&params, push_config("t1"))
                .await
                .unwrap_err();
            assert_eq!(error.code, error_code::PUSH_NOTIFICATION_NOT_SUPPORTED);
        }
    }

    /// `with_push_notifications` defaults the capability the same way as
    /// `with_push_config_store`, and likewise must not override an explicit
    /// `false`. It had no unit test before #203 — only an example — so the
    /// two builders could have drifted apart unnoticed.
    #[tokio::test]
    async fn test_with_push_notifications_defaults_the_capability() {
        let params = ServiceParams::new();

        let handler = make_handler().with_push_notifications(
            InMemoryPushConfigStore::new(),
            crate::HttpPushSender::new(None),
        );
        assert_eq!(handler.capabilities.push_notifications, Some(true));
        assert!(
            handler
                .create_push_config(&params, push_config("t1"))
                .await
                .is_ok()
        );

        let handler = make_handler()
            .with_capabilities(caps(None, Some(false)))
            .with_push_notifications(
                InMemoryPushConfigStore::new(),
                crate::HttpPushSender::new(None),
            );
        assert_eq!(handler.capabilities.push_notifications, Some(false));
        let error = handler
            .create_push_config(&params, push_config("t1"))
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::PUSH_NOTIFICATION_NOT_SUPPORTED);
    }

    /// A store that was never supplied still reports the same code — that is
    /// the deployment state, distinct from the card's declaration.
    #[tokio::test]
    async fn test_missing_store_still_reports_push_unsupported() {
        let handler = make_handler();
        let error = handler
            .create_push_config(&ServiceParams::new(), push_config("t1"))
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::PUSH_NOTIFICATION_NOT_SUPPORTED);
    }

    /// Reported in #161 against a different crate (`a2a-protocol-server`),
    /// but worth pinning here: two tasks sharing a `contextId` must each
    /// carry only their own artifacts. The task store is keyed by task id,
    /// so there is no path by which a context could aggregate them — this
    /// test exists so that stays true.
    #[tokio::test]
    async fn test_artifacts_do_not_aggregate_across_tasks_in_one_context() {
        let handler = make_handler();
        let params = ServiceParams::new();
        let context_id = "ctx-shared";

        for (task_id, artifact_id) in [("t-first", "a-1"), ("t-second", "a-2")] {
            handler
                .task_store
                .create(Task {
                    id: task_id.into(),
                    context_id: context_id.into(),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: None,
                    },
                    artifacts: None,
                    history: None,
                    metadata: None,
                })
                .await
                .unwrap();

            apply_event_to_task(
                handler.task_store.as_ref(),
                None,
                &StreamResponse::ArtifactUpdate(TaskArtifactUpdateEvent {
                    task_id: task_id.into(),
                    context_id: context_id.into(),
                    artifact: Artifact {
                        artifact_id: artifact_id.into(),
                        name: None,
                        description: None,
                        parts: vec![Part::text("payload")],
                        metadata: None,
                        extensions: None,
                    },
                    append: None,
                    last_chunk: None,
                    metadata: None,
                }),
            )
            .await
            .unwrap();
        }

        for (task_id, expected) in [("t-first", "a-1"), ("t-second", "a-2")] {
            let task = handler
                .get_task(
                    &params,
                    GetTaskRequest {
                        id: task_id.into(),
                        history_length: None,
                        tenant: None,
                    },
                )
                .await
                .unwrap();
            let ids: Vec<&str> = task
                .artifacts
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|a| a.artifact_id.as_str())
                .collect();
            assert_eq!(
                ids,
                vec![expected],
                "{task_id} must carry only its own artifact"
            );
        }
    }
    // §12.4 / §10.1 (#204): the extended Agent Card.

    fn extended_card(name: &str) -> AgentCard {
        AgentCard {
            name: name.into(),
            description: "extended".into(),
            version: "1.0".into(),
            supported_interfaces: vec![],
            capabilities: AgentCapabilities::default(),
            default_input_modes: vec![],
            default_output_modes: vec![],
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security_requirements: None,
            signatures: None,
        }
    }

    fn extended_request() -> GetExtendedAgentCardRequest {
        GetExtendedAgentCardRequest { tenant: None }
    }

    #[tokio::test]
    async fn test_extended_agent_card_is_served_when_configured() {
        let handler = make_handler().with_extended_agent_card(extended_card("secret skills"));
        let card = handler
            .get_extended_agent_card(&ServiceParams::new(), extended_request())
            .await
            .unwrap();
        assert_eq!(card.name, "secret skills");
    }

    /// Configuring a card also declares the capability, so serving one and
    /// advertising it are not two things to remember.
    #[tokio::test]
    async fn test_configuring_an_extended_card_declares_the_capability() {
        let handler = make_handler().with_extended_agent_card(extended_card("x"));
        assert_eq!(handler.capabilities.extended_agent_card, Some(true));
    }

    /// A2A gives this condition its own code. Before #204 it reported
    /// `UNSUPPORTED_OPERATION`, which says the agent does not do extended
    /// cards at all rather than that this deployment has not configured one.
    #[tokio::test]
    async fn test_unconfigured_extended_card_reports_its_own_code() {
        let handler = make_handler().with_capabilities(AgentCapabilities {
            streaming: None,
            push_notifications: None,
            extensions: None,
            extended_agent_card: Some(true),
        });
        let error = handler
            .get_extended_agent_card(&ServiceParams::new(), extended_request())
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::EXTENDED_CARD_NOT_CONFIGURED);
        assert_ne!(error.code, error_code::UNSUPPORTED_OPERATION);
    }

    /// The capability gate from #203 runs first: a card declaring
    /// `extendedAgentCard: false` refuses before the configured/unconfigured
    /// distinction is even reached.
    #[tokio::test]
    async fn test_capability_gate_precedes_the_not_configured_check() {
        let handler = make_handler()
            .with_extended_agent_card(extended_card("x"))
            .with_capabilities(AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extensions: None,
                extended_agent_card: Some(false),
            });
        let error = handler
            .get_extended_agent_card(&ServiceParams::new(), extended_request())
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION);
    }

    /// §12.4 fetches the extended card under a security scheme, so a
    /// resolver can vary what it reveals by caller.
    #[tokio::test]
    async fn test_resolver_sees_the_caller_params() {
        let handler = make_handler().with_extended_agent_card_resolver(|params: &ServiceParams| {
            let privileged = params.contains_key("x-privileged");
            Ok(extended_card(if privileged { "full" } else { "limited" }))
        });

        let card = handler
            .get_extended_agent_card(&ServiceParams::new(), extended_request())
            .await
            .unwrap();
        assert_eq!(card.name, "limited");

        let mut params = ServiceParams::new();
        params.insert("x-privileged".into(), vec!["yes".into()]);
        let card = handler
            .get_extended_agent_card(&params, extended_request())
            .await
            .unwrap();
        assert_eq!(card.name, "full");
    }
}

#[cfg(test)]
mod lag_coverage_tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_subscription_lag_is_reported_as_a_sanitized_internal_error() {
        // A subscriber that falls behind the active execution gets a generic
        // INTERNAL_ERROR rather than the broadcast internals, and the stream
        // terminates instead of spinning on a lost buffer.
        let (sender, receiver) = broadcast::channel(1);

        for sequence in 0..4 {
            let _ = sender.send(ExecutionEvent {
                sequence,
                result: Ok(StreamResponse::Message(a2a::Message {
                    message_id: "lag-probe".to_string(),
                    role: a2a::Role::Agent,
                    parts: Vec::new(),
                    context_id: None,
                    task_id: None,
                    metadata: None,
                    extensions: None,
                    reference_task_ids: None,
                })),
            });
        }

        let mut stream = subscription_stream(receiver, None, 0);
        let item = stream.next().await.expect("lagged item");

        let error = item.expect_err("lag must surface as an error");
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
        assert_eq!(error.message, "Internal error");

        // `done` is set on lag, so the stream ends rather than repeating.
        assert!(stream.next().await.is_none());
    }
}
