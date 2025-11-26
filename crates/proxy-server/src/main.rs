use anyhow::Context;
use clap::Parser;
use config::CallbackSignature;
use kumo_server_common::diagnostic_logging::{DiagnosticFormat, LoggingConfig};
use kumo_server_common::start::StartConfig;
use nix::sys::resource::{getrlimit, setrlimit, Resource};
use std::path::PathBuf;

mod mod_proxy;
mod proxy_handler;

/// KumoProxy SOCKS5 Proxy Server.
///
/// Full docs available at: <https://docs.kumomta.com>
#[derive(Debug, Parser)]
#[command(about, version=version_info::kumo_version())]
struct Opt {
    /// Lua policy file to load.
    #[arg(long, default_value = "/opt/kumomta/etc/proxy/init.lua")]
    policy: PathBuf,

    /// Directory where diagnostic log files will be placed.
    ///
    /// If omitted, diagnostics will be printed to stderr.
    #[arg(long)]
    diag_log_dir: Option<PathBuf>,

    /// How diagnostic logs render. full, compact and pretty are intended
    /// for human consumption.
    ///
    /// json outputs machine readable records.
    #[arg(long, default_value = "full")]
    diag_format: DiagnosticFormat,
}

fn main() -> anyhow::Result<()> {
    let opts = Opt::parse();

    let (_no_file_soft, no_file_hard) = getrlimit(Resource::RLIMIT_NOFILE)?;
    setrlimit(Resource::RLIMIT_NOFILE, no_file_hard, no_file_hard).context("setrlimit NOFILE")?;

    kumo_server_common::panic::register_panic_hook();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_park(kumo_server_memory::purge_thread_cache)
        .build()
        .unwrap()
        .block_on(async move { run(opts).await })
}

async fn perform_init() -> anyhow::Result<()> {
    tracing::info!("Version is {}", version_info::kumo_version());
    let mut config = config::load_config().await?;

    let proxy_init_sig = CallbackSignature::<(), ()>::new("proxy_init");

    config
        .async_call_callback(&proxy_init_sig, ())
        .await
        .context("in proxy_init event")?;
    config.put();

    Ok(())
}

async fn signal_shutdown() {
    tracing::info!("shutting down");
}

async fn run(opts: Opt) -> anyhow::Result<()> {
    kumo_server_runtime::assign_main_runtime(tokio::runtime::Handle::current());
    StartConfig {
        logging: LoggingConfig {
            log_dir: opts.diag_log_dir.clone(),
            diag_format: opts.diag_format,
            filter_env_var: "KUMO_PROXY_LOG",
            default_filter: "proxy_server=info,kumo_server_common=info,kumo_server_runtime=info",
        },
        lua_funcs: &[kumo_server_common::register, mod_proxy::register],
        policy: &opts.policy,
    }
    .run(perform_init(), signal_shutdown())
    .await
}
