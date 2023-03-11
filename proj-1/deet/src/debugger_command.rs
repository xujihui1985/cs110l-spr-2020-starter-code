pub enum DebuggerCommand {
    Quit,
    Run(Vec<String>),
    Cont(Vec<String>),
    Break(Vec<String>),
    Backtrace,
}

impl DebuggerCommand {
    pub fn from_tokens(tokens: &[&str]) -> Option<DebuggerCommand> {
        match tokens[0] {
            "q" | "quit" => Some(DebuggerCommand::Quit),
            "r" | "run" => {
                Some(DebuggerCommand::Run(get_args(tokens[1..].to_vec())))
            },
            "c" | "cont" => {
                Some(DebuggerCommand::Cont(get_args(tokens[1..].to_vec())))
            },
            "b" | "break" => {
                Some(DebuggerCommand::Break(get_args(tokens[1..].to_vec())))
            },
            "bt" | "backtrace" => Some(DebuggerCommand::Backtrace),
            // Default case:
            _ => None,
        }
    }
}

fn get_args(args: Vec<&str>) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}
