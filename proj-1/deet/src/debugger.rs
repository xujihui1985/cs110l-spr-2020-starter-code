use std::collections::HashMap;
use std::io;
use std::ops::Sub;

use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::DwarfData;
use crate::dwarf_data::Error::{DwarfFormatError, ErrorOpeningFile};
use crate::inferior::Inferior;
use rustyline::error::ReadlineError;
use rustyline::Editor;

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
    break_points: HashMap<usize, Option<Breakpoint>>,
}

#[derive(Clone)]
struct Breakpoint {
    addr: usize,
    orig_byte: u8,
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> std::io::Result<Debugger> {
        // TODO (milestone 3): initialize the DwarfData

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(ErrorOpeningFile) => {
                println!("could not open file {}", target);
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(DwarfFormatError(e)) => {
                println!("could not find debug info open file {}, {:?}", target, e);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        };
        debug_data.print();

        Ok(Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data,
            break_points: HashMap::new(),
        })
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if let Some(inferior) = self.inferior.take() {
                        if let Err(e) = inferior.kill() {
                            println!("failed to kill origin running process {}", e);
                            continue;
                        }
                    }
                    if let Some(inferior) = Inferior::new(&self.target, &args) {
                        // Create the inferior
                        // set breakpoints to inferior
                        for (addr, v) in &mut self.break_points {
                            if let Ok(orig_addr) = inferior.set_breakpoint(*addr) {
                                *v = Some(Breakpoint {
                                    orig_byte: orig_addr,
                                    addr: *addr,
                                });
                            }
                        }
                        self.inferior = Some(inferior);

                        match self.inferior.as_ref().unwrap().cont() {
                            Ok(st) => {
                                self.inferior.as_mut().unwrap().set_status(&st);
                                if let crate::inferior::Status::Stopped(sig, rip) = st {
                                    let line = self.debug_data.get_line_from_addr(rip).unwrap();
                                    println!("Child stopped (signal {:?}), rip {:#x}", sig, rip);
                                    println!("Stopped at {}", line);
                                }
                            }
                            Err(e) => eprintln!("failed to continue debugger {}", e),
                        }
                    } else {
                        println!("Error starting subprocess");
                    }
                }
                DebuggerCommand::Break(args) => {
                    for break_point in args {
                        let addr = {
                            if let Some(maybe_line_number) = break_point.parse::<usize>().ok() {
                                DwarfData::get_addr_for_line(&self.debug_data, None, maybe_line_number)
                            } else {
                                DwarfData::get_addr_for_function(&self.debug_data, None, &break_point)
                            }
                        };
                        if let Some(addr) = addr {
                            self.break_points.insert(addr, None);
                        } else {
                            println!("failed to set break point for {}", break_point);
                        }
                    }
                }
                DebuggerCommand::Cont(_args) => {
                    if let Some(ref inferior) = self.inferior {
                        // if current status of inferior is in stop status, get the rip
                        if let crate::inferior::Status::Stopped(_sig, rip) = inferior.get_status() {
                            if let Some(obp) = self.break_points.get(&(rip.sub(1))) {
                                if let Some(bp) = obp {
                                    if let Err(e) = inferior
                                        .unset_breakpoint(bp.addr, bp.orig_byte)
                                        .and_then(|_| inferior.step_back(rip))
                                        .and_then(|_| inferior.step())
                                        .and_then(|_| inferior.set_breakpoint(bp.addr))
                                    {
                                        println!("failed to cont from breakpoint {}", e);
                                    }
                                }
                            }
                        }
                        if let Err(e) = inferior.cont() {
                            println!("failed to continue run process {}", e);
                        }
                    } else {
                        println!("No inferior is running");
                    }
                }
                DebuggerCommand::Backtrace => {
                    if let Some(ref inferior) = self.inferior {
                        if let Err(e) = inferior.print_backtrace(&self.debug_data) {
                            println!("failed to print backtrace of process {}", e);
                            continue;
                        }
                    } else {
                        println!("No inferior is running");
                    }
                }
                DebuggerCommand::Quit => {
                    return;
                }
            }
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}
