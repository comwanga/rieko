pub use rieko_cli::agent::AgentArgs as ServeArgs;

pub fn run(args: ServeArgs) -> anyhow::Result<()> {
    rieko_cli::agent::run(args)
}
