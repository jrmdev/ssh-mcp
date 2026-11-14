use std::{path::PathBuf, time::Duration};

use clap::Parser;
use rmcp::ServiceExt;
use ssh_mcp::{config::Config, server::SshMcp, ssh::ConnectionManager};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// SSH configuration file. Defaults to the user's .ssh/config.
    #[arg(long)]
    config: Option<PathBuf>,
    /// System OpenSSH executable used only for configuration resolution.
    #[arg(long, default_value = if cfg!(windows) { "ssh.exe" } else { "ssh" })]
    ssh: PathBuf,
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let server = SshMcp::new(ConnectionManager::new(Config::new(cli.config, cli.ssh)?));
    let running = server.clone().serve(rmcp::transport::stdio_pipes()).await?;
    let cancellation = running.cancellation_token();
    let waiting = running.waiting();
    tokio::pin!(waiting);
    let service_result = tokio::select! {
        result = &mut waiting => result.map(|_| ()),
        _ = tokio::signal::ctrl_c() => { cancellation.cancel(); Ok(()) }
        _ = terminate_signal() => { cancellation.cancel(); Ok(()) }
    };
    // Bound cleanup even if the transport or remote server is unresponsive.
    if tokio::time::timeout(Duration::from_secs(10), server.shutdown())
        .await
        .is_err()
    {
        eprintln!("ssh-mcp: shutdown timed out; remote job outcomes may be unknown");
    }
    service_result?;
    Ok(())
}

#[cfg(unix)]
async fn terminate_signal() {
    if let Ok(mut signal) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        signal.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("create Tokio runtime");
    let status = match runtime.block_on(run()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("ssh-mcp: {error:#}");
            1
        }
    };
    // Tokio's blocking stdin reader cannot be cancelled on Windows.
    runtime.shutdown_timeout(Duration::from_secs(1));
    std::process::exit(status);
}
