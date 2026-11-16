use std::{future::Future, sync::Arc};

use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Implementation, ServerCapabilities, ServerConfig},
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    files::{self, DownloadFile, EditFile, ReadFile, UploadFile, WriteFile},
    jobs::{CancelJob, ExecuteCommand, GetJob, JobManager},
    ssh::ConnectionManager,
};

#[derive(Clone)]
pub struct SshMcp {
    connections: Arc<ConnectionManager>,
    jobs: Arc<JobManager>,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    /// A literal Host alias returned by list_hosts.
    pub alias: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionId {
    pub session_id: String,
}

fn result(value: anyhow::Result<serde_json::Value>) -> CallToolResult {
    match value {
        Ok(value) => CallToolResult::structured(value),
        Err(error) => CallToolResult::structured_error(json!({"error": format!("{error:#}")})),
    }
}

async fn cancellable(
    context: RequestContext<RoleServer>,
    operation: impl Future<Output = anyhow::Result<serde_json::Value>>,
) -> CallToolResult {
    tokio::select! {
        biased;
        _ = context.ct.cancelled() => result(Err(anyhow::anyhow!("request cancelled; a submitted remote mutation may already have taken effect"))),
        value = operation => result(value),
    }
}

#[tool_router]
impl SshMcp {
    pub fn new(connections: ConnectionManager) -> Self {
        Self {
            connections: Arc::new(connections),
            jobs: Arc::new(JobManager::new()),
            tool_router: Self::tool_router(),
        }
    }

    pub async fn shutdown(&self) {
        self.jobs.shutdown().await;
        self.connections.shutdown().await;
    }

    #[tool(
        description = "Discover literal Host aliases from the local SSH config. No remote connection is opened.",
        annotations(read_only_hint = true)
    )]
    async fn list_hosts(&self) -> CallToolResult {
        result(self.connections.list_hosts().await)
    }

    #[tool(
        description = "Connect to a configured SSH alias, reusing its persistent connection when already connected. Host keys must already be trusted locally."
    )]
    async fn connect(
        &self,
        Parameters(input): Parameters<Connect>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.connect(&input.alias).await?;
            Ok(json!({
                "session_id": session.id, "alias": session.alias,
                "hostname": session.hostname, "user": session.user,
                "port": session.port, "home": session.home,
                "shell": if crate::files::windows_home(&session.home) { "powershell" } else { "posix" },
            }))
        })
        .await
    }

    #[tool(
        description = "List persistent SSH sessions and their status.",
        annotations(read_only_hint = true)
    )]
    async fn list_sessions(&self) -> CallToolResult {
        result(Ok(self.connections.list_sessions().await))
    }

    #[tool(
        description = "Cancel this session's jobs on a best-effort basis and close its SSH connection."
    )]
    async fn disconnect(&self, Parameters(input): Parameters<SessionId>) -> CallToolResult {
        if let Err(error) = self.connections.stop_commands(&input.session_id).await {
            return result(Err(error));
        }
        self.jobs.cancel_session(&input.session_id).await;
        result(
            self.connections
                .disconnect(&input.session_id)
                .await
                .map(|()| json!({"disconnected": true})),
        )
    }

    #[tool(
        description = "Read a remote file through SFTP. Paths are literal and relative paths start at remote home. Use pagination or base64 for binary content.",
        annotations(read_only_hint = true)
    )]
    async fn read_file(
        &self,
        Parameters(input): Parameters<ReadFile>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.get(&input.session_id).await?;
            files::read_file(&session, input).await
        })
        .await
    }

    #[tool(
        description = "Atomically create or replace a remote file with up to 1 MiB of UTF-8/base64 content. An expected SHA-256 can reject stale content."
    )]
    async fn write_file(
        &self,
        Parameters(input): Parameters<WriteFile>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.get(&input.session_id).await?;
            files::write_file(&session, input).await
        })
        .await
    }

    #[tool(
        description = "Edit a remote UTF-8 file by exact text replacement. Exactly one match is required unless replace_all is true. Supports an expected SHA-256."
    )]
    async fn edit_file(
        &self,
        Parameters(input): Parameters<EditFile>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.get(&input.session_id).await?;
            files::edit_file(&session, input).await
        })
        .await
    }

    #[tool(
        description = "Run a noninteractive command using a POSIX shell on Unix or Windows PowerShell on Windows. Returns a job ID; poll with get_job. cwd and environment are per-command. Output and job state live only in local memory."
    )]
    async fn execute_command(
        &self,
        Parameters(input): Parameters<ExecuteCommand>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.get(&input.session_id).await?;
            self.jobs.execute(session, input).await
        })
        .await
    }

    #[tool(
        description = "Poll a command job using raw-byte stdout/stderr offsets. Output is UTF-8 with invalid bytes replaced. Truncation is explicit; wait_ms is capped at 30 seconds.",
        annotations(read_only_hint = true)
    )]
    async fn get_job(
        &self,
        Parameters(input): Parameters<GetJob>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, self.jobs.get(input)).await
    }

    #[tool(
        description = "Request TERM, then KILL after two seconds if necessary. Only a confirmed remote exit proves termination; detached descendants can survive."
    )]
    async fn cancel_job(&self, Parameters(input): Parameters<CancelJob>) -> CallToolResult {
        result(self.jobs.cancel(&input.job_id).await)
    }

    #[tool(
        description = "Stream a local file to a remote path over SFTP without putting its contents in the model context. Refuses overwrite by default."
    )]
    async fn upload_file(
        &self,
        Parameters(input): Parameters<UploadFile>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.get(&input.session_id).await?;
            files::upload_file(&session, input).await
        })
        .await
    }

    #[tool(
        description = "Stream a remote file to a local path over SFTP without putting its contents in the model context. Refuses overwrite by default."
    )]
    async fn download_file(
        &self,
        Parameters(input): Parameters<DownloadFile>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        cancellable(context, async {
            let session = self.connections.get(&input.session_id).await?;
            files::download_file(&session, input).await
        })
        .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ssh-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions("Local tools over persistent SSH connections. Start with list_hosts, then connect; pass its session_id to remote tools. File paths are literal, relative to remote home. Commands use explicit cwd/env and do not share shell state. Do not replay a mutation whose outcome is unknown after connection loss. No credentials are accepted through tool arguments.")
    }
}
