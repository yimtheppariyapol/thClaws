//! `POST /agent/run` — thClaws-native agent endpoint.
//!
//! Where `/v1/chat/completions` is the OpenAI-compatible surface for
//! external clients (Cursor, Aider, n8n, …), `/agent/run` is the
//! agent-shaped surface for orchestrators that treat thClaws as a
//! sovereign agent peer (paperclip-adapter / thcompany). It takes an
//! explicit `workspace_dir` and runs the full skill / MCP / plugin /
//! policy bootstrap scoped to that directory — see
//! `dev-plan/25-thclaws-as-agent.md`.
//!
//! Wire shape mirrors `/v1/chat/completions` for the parts that map
//! cleanly (sync JSON, SSE stream, `x_callback` async) but emits
//! native thClaws SSE events instead of OpenAI chunks. That lets
//! orchestrators consume tool calls + skill invocations without
//! pretending they're OpenAI tokens.

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;

use super::callback::{deliver, CallbackPayload, CallbackTarget};
use super::chat::XCallback;
use super::errors::OpenAiError;
use super::AuthOk;
use crate::agent::{collect_agent_turn, AgentEvent, AgentTurnOutcome};
use crate::agent_runtime::{build_runtime_for_workspace, validate_workspace_dir};
use crate::config::AppConfig;

// ── request shape ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AgentRunRequest {
    pub prompt: String,
    /// Absolute path to the per-agent workspace. Read-from for skill /
    /// MCP / policy discovery; read+write for any file tool the agent
    /// invokes. Validated against `THCLAWS_AGENT_WORKSPACE_ROOT` when
    /// set (see [`crate::agent_runtime::validate_workspace_dir`]).
    pub workspace_dir: String,
    /// Optional extra system prompt. Appended to the thClaws default
    /// + skill catalog — does NOT replace them.
    #[serde(default)]
    pub system: Option<String>,
    /// Optional model id override. Defaults to whatever the daemon
    /// config carries.
    #[serde(default)]
    pub model: Option<String>,
    /// Reserved for session resume across turns. Phase A does not
    /// implement persistence yet — the field is accepted but ignored.
    #[serde(default)]
    pub session_id: Option<String>,
    /// `true` (default) → SSE stream of native agent events.
    /// `false` → wait for completion, return one JSON result.
    /// Ignored when `x_callback` is present (async always 202s).
    #[serde(default = "default_stream")]
    pub stream: bool,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// Fire-and-forget mode. Same envelope as
    /// `chat_completions::XCallback` — handler returns 202 ACK
    /// immediately and POSTs the terminal payload to the callback URL
    /// when the run finishes.
    #[serde(default)]
    pub x_callback: Option<XCallback>,
}

fn default_stream() -> bool {
    true
}

// ── handler ───────────────────────────────────────────────────────────

pub async fn agent_run(
    _auth: AuthOk,
    Json(req): Json<AgentRunRequest>,
) -> Result<Response, Response> {
    // Validate workspace_dir up-front so all paths (sync/SSE/async)
    // share the same 400 surface.
    let workspace_dir = validate_workspace_dir(&req.workspace_dir).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::invalid_request(msg, "invalid_workspace_dir")),
        )
            .into_response()
    })?;

    if let Some(callback) = req.x_callback.clone() {
        return agent_run_async(req, workspace_dir, callback).await;
    }

    if req.stream {
        return agent_run_stream(req, workspace_dir).await;
    }

    agent_run_sync(req, workspace_dir).await
}

// ── sync (non-stream) path ────────────────────────────────────────────

async fn agent_run_sync(
    req: AgentRunRequest,
    workspace_dir: std::path::PathBuf,
) -> Result<Response, Response> {
    let model = effective_config(&req).model;
    let outcome = run_outcome(&req, &workspace_dir).await.map_err(|e| {
        let msg = format!("{e}");
        eprintln!("[api_v1] agent_run sync failure: {msg}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OpenAiError::server_error(msg)),
        )
            .into_response()
    })?;
    let usage = outcome.usage.unwrap_or_default();
    Ok(Json(json!({
        "model": model,
        "workspace_dir": workspace_dir.display().to_string(),
        "summary": outcome.text,
        "stop_reason": outcome.stop_reason,
        "iterations": outcome.iterations,
        "usage": {
            "prompt_tokens": usage.input_tokens,
            "completion_tokens": usage.output_tokens,
            "cached_input_tokens": usage.cache_read_input_tokens,
            "cache_creation_input_tokens": usage.cache_creation_input_tokens,
            "reasoning_output_tokens": usage.reasoning_output_tokens,
        },
    }))
    .into_response())
}

// ── SSE stream path ───────────────────────────────────────────────────

async fn agent_run_stream(
    req: AgentRunRequest,
    workspace_dir: std::path::PathBuf,
) -> Result<Response, Response> {
    let config = effective_config(&req);
    let runtime = build_runtime_for_workspace(&config, &workspace_dir, req.system.as_deref())
        .await
        .map_err(|e| {
            let msg = format!("{e}");
            eprintln!("[api_v1] agent_run stream setup failure: {msg}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpenAiError::server_error(msg)),
            )
                .into_response()
        })?;

    let model_for_stream = config.model.clone();
    let prompt = req.prompt;
    let stream = async_stream::stream! {
        // Keep the runtime alive (MCP subprocesses, skill store handle)
        // until the stream finishes. Move it into the generator body
        // so its Drop happens after the last yield.
        let runtime = runtime;

        let mut turn = Box::pin(runtime.agent.run_turn(prompt));
        let mut emitted_error = false;
        while let Some(ev) = turn.next().await {
            match ev {
                Ok(AgentEvent::Text(s)) => {
                    if !s.is_empty() {
                        yield Ok::<_, Infallible>(named_event("text", json!({ "delta": s })));
                    }
                }
                Ok(AgentEvent::Thinking(s)) => {
                    if !s.is_empty() {
                        yield Ok(named_event("thinking", json!({ "delta": s })));
                    }
                }
                Ok(AgentEvent::ToolCallStart { id, name, input }) => {
                    // Skill invocations are tool calls under the hood
                    // (the `Skill` tool); surface them as a distinct
                    // event so consumers don't have to special-case
                    // the tool name on every parse.
                    let event_name = if name == "Skill" { "skill_invoked" } else { "tool_use_start" };
                    yield Ok(named_event(event_name, json!({
                        "id": id,
                        "name": name,
                        "input": input,
                    })));
                }
                Ok(AgentEvent::ToolCallResult { id, name, output, .. }) => {
                    let (status, payload) = match output {
                        Ok(s) => ("ok", s),
                        Err(s) => ("error", s),
                    };
                    let event_name = if name == "Skill" { "skill_invoked_result" } else { "tool_use_result" };
                    yield Ok(named_event(event_name, json!({
                        "id": id,
                        "name": name,
                        "status": status,
                        "output": payload,
                    })));
                }
                Ok(AgentEvent::ToolCallDenied { id, name }) => {
                    yield Ok(named_event("tool_use_denied", json!({
                        "id": id,
                        "name": name,
                    })));
                }
                Ok(AgentEvent::IterationStart { .. }) => {}
                Ok(AgentEvent::Done { stop_reason, usage }) => {
                    yield Ok(named_event("usage", json!({
                        "prompt_tokens": usage.input_tokens,
                        "completion_tokens": usage.output_tokens,
                        "cached_input_tokens": usage.cache_read_input_tokens,
                        "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                        "reasoning_output_tokens": usage.reasoning_output_tokens,
                    })));
                    yield Ok(named_event("result", json!({
                        "model": model_for_stream,
                        "stop_reason": stop_reason,
                    })));
                }
                Err(e) => {
                    emitted_error = true;
                    yield Ok(named_event("error", json!({
                        "message": format!("{e}"),
                    })));
                    break;
                }
            }
        }

        if !emitted_error {
            // Terminal sentinel — clients can use this as an unambiguous
            // end-of-stream marker instead of waiting for connection close.
            yield Ok(Event::default().data("[DONE]"));
        }
    };

    let sse = Sse::new(stream).keep_alive(KeepAlive::new());
    Ok(sse.into_response())
}

// ── async (x_callback) path ───────────────────────────────────────────

async fn agent_run_async(
    req: AgentRunRequest,
    workspace_dir: std::path::PathBuf,
    callback: XCallback,
) -> Result<Response, Response> {
    let target = CallbackTarget::from_request(&callback).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::invalid_request(e, "invalid_x_callback")),
        )
            .into_response()
    })?;

    let run_id = target.run_id.clone();
    let model = req.model.clone().unwrap_or_default();
    let started_at = chrono::Utc::now();

    let target_for_task = target.clone();
    let model_for_task = model.clone();
    let run_id_for_task = run_id.clone();
    let workspace_for_task = workspace_dir.clone();
    let req_for_task = req;
    let handle = tokio::spawn(async move {
        let outcome = run_outcome(&req_for_task, &workspace_for_task).await;
        let payload =
            CallbackPayload::from_outcome(&run_id_for_task, &model_for_task, started_at, outcome);
        deliver(&target_for_task, &payload).await;
    });

    let watch_run_id = run_id.clone();
    let watch_target = target.clone();
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => {}
            Err(join_err) if join_err.is_panic() => {
                eprintln!(
                    "[api_v1] agent_run async callback_failed run_id={} reason=task_panicked",
                    watch_run_id
                );
                let payload = CallbackPayload::panic_payload(&watch_run_id, started_at);
                deliver(&watch_target, &payload).await;
            }
            Err(join_err) => {
                eprintln!(
                    "[api_v1] agent_run async callback_failed run_id={} reason=task_cancelled error=\"{join_err}\"",
                    watch_run_id
                );
            }
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "run_id": run_id,
            "status": "accepted",
            "model": model,
            "workspace_dir": workspace_dir.display().to_string(),
        })),
    )
        .into_response())
}

// ── shared internals ──────────────────────────────────────────────────

async fn run_outcome(
    req: &AgentRunRequest,
    workspace_dir: &std::path::Path,
) -> crate::error::Result<AgentTurnOutcome> {
    let config = effective_config(req);
    let runtime =
        build_runtime_for_workspace(&config, workspace_dir, req.system.as_deref()).await?;
    let turn = runtime.agent.run_turn(req.prompt.clone());
    collect_agent_turn(turn).await
}

fn effective_config(req: &AgentRunRequest) -> AppConfig {
    let mut config = AppConfig::load().unwrap_or_default();
    if let Some(m) = req.model.as_ref().filter(|s| !s.trim().is_empty()) {
        config.model = m.clone();
    }
    if let Some(max) = req.max_tokens {
        config.max_tokens = max;
    }
    let _ = req.temperature; // reserved; not all providers honor it
    config
}

fn named_event(name: &str, payload: serde_json::Value) -> Event {
    Event::default().event(name).data(payload.to_string())
}
