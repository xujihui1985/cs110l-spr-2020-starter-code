use nix::sys::ptrace;
use nix::sys::ptrace::AddressType;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::ops::{Add, Sub};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use crate::dwarf_data::DwarfData;

#[derive(Debug, Clone, Copy)]
pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),

    Init,
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

pub struct Inferior {
    child: Child,
    status: Status
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>) -> Option<Inferior> {
        // TODO: implement me!
        let mut cmd = Command::new(target);
        let cmd = cmd.args(args);
        unsafe { cmd.pre_exec(child_traceme) };
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(_) => return None,
        };
        let inferior = Self { child, status: Status::Init };
        match inferior.wait(None) {
            Ok(st) => match st {
                Status::Stopped(sig, _) => {
                    println!("Child stopped (signal {:?})", sig);
                    Some(inferior)
                }
                _ => None,
            },
            Err(_) => None,
        }
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    pub fn cont(&self) -> Result<Status, nix::Error> {
        ptrace::cont(self.pid(), None)?;
        self.wait(None)
    }

    pub fn kill(mut self) -> Result<Status, nix::Error> {
        self.child.kill().map_err(|_| nix::Error::Sys(nix::errno::Errno::EBADE))?;
        self.wait(None)
    }

    pub fn print_backtrace(&self, debug_data: &DwarfData) -> Result<(), nix::Error> {
        let reg = ptrace::getregs(self.pid())?;
        let mut base_rip = reg.rip; // the instruction pointer
        let mut base_rbp = reg.rbp; // the value of rbp is saved rbp of last stack frame
        loop {
            Self::print_rip_func(base_rip as usize, debug_data);
            let fn_name = debug_data.get_function_from_addr(base_rip as usize).unwrap();
            if fn_name == "main" {
                break;
            }
            base_rip = ptrace::read(self.pid(), base_rbp.add(8) as AddressType)? as u64;
            base_rbp = ptrace::read(self.pid(), base_rbp as AddressType)? as u64;
        }
        Ok(())
    }

    fn print_rip_func(addr: usize, debug_data: &DwarfData) {
        let line = debug_data
        .get_line_from_addr(addr).unwrap();
        let fn_name = debug_data
        .get_function_from_addr(addr).unwrap();
        println!("{} ({})", fn_name, line);
    }

    fn write_byte(&self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = align_addr_to_word(addr);
        println!("origin_addr {:#x}", addr);
        println!("aligned_addr {:#x}", aligned_addr);
        let byte_offset = addr - aligned_addr;
        println!("offset {:#x}", byte_offset);
        let word = ptrace::read(self.pid(), aligned_addr as AddressType)? as u64;
        println!("aligned word {:#x}", word);
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        println!("orig_byte {:#x}", orig_byte);
        let masked_word = word & !(0xff << 8 * byte_offset);
        println!("masked_word {:#x}", masked_word);
        println!("val to update {:#x}", (val as u64) << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        println!("updated_word {:#x}", updated_word);
        ptrace::write(
            self.pid(),
            aligned_addr as AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }

    pub fn set_breakpoint(&self, addr: usize) -> Result<u8, nix::Error> {
        self.write_byte(addr, 0xcc)
    }

    pub fn unset_breakpoint(&self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        self.write_byte(addr, val)
    }

    pub fn step(&self) -> Result<Status, nix::Error> {
        ptrace::step(self.pid(), None)?;
        self.wait(None)
    }

    pub fn set_status(&mut self, s: &Status) {
        self.status = *s;
    }

    pub fn get_status(&self) -> Status {
        self.status
    }

    pub fn step_back(&self, rip: usize) -> Result<(), nix::Error>{
        let mut reg = ptrace::getregs(self.pid())?;
        reg.rip = rip.sub(1) as u64;
        ptrace::setregs(self.pid(), reg)
    }

}

fn align_addr_to_word(addr: usize) -> usize {
    addr & (-(std::mem::size_of::<usize>() as isize) as usize)
}
