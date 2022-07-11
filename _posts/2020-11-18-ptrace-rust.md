---
layout: post
title: "System programming with Rust"
date: 2020-11-18
tags:
- System programming
- Rust
---

Back in May I started a blog post [series](https://carstein.github.io/2020/04/18/writing-simple-fuzzer-1.html) explaining how to write simple fuzzers. Few episodes down this path I've faced a difficult challenge - do I continue writing my fuzzer using Python or should I switch to some other, more suitable language.

Sticking to Python wasn't an unpleasant idea - it is a simple language and I can use it pretty fluently. There were some big disadvantages as well. First of all, I was using an external `ptrace` library and I didn't feel like modifying it too much. I don't even want to mention speed and  concurrency issues. With full awareness that it might put me back in square one when it comes to progress I've decided to rewrite and hopefully continue the series in Rust. There was only one problem - I didn't know Rust.

Still, I'm back from paternity leave with a strong resolution of wrapping some subjects up and learning some Rust in the process.

# System programming in Rust

I've always believed in sharing with a broader community, especially if you are sharing something that you were unable to find yourself in the first place. When it comes to system programming, the Internet is not particularly rich in code samples or articles explaining how to translate ideas you've picked up from C into an efficient code in Rust. Don't worry - I'm here to share with you how to use `fork` and `ptrace` in Rust. I hope you will find it handy.

## How to eat with fork

I will gradually introduce certain concepts as we go, but let us begin with a main code skeleton. When it comes to external libraries we will be using, I need to mention [nix](https://crates.io/crates/nix) and [linux-personality]( https://crates.io/crates/linux-personality).  First one is a a collection of Rust bindings to various \*nix APIs while second will allow us to disable `ASLR` for the child process.

```rust
fn main() {
    // breakpoints to set
    let breakpoints: [u64; 1] = [0x8048451]; 

    match unsafe{fork()} {
        
        Ok(ForkResult::Child) => {
            run_child();
        }
        
        Ok(ForkResult::Parent {child}) => {
            run_parent(child, &breakpoints);
        }
        
        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    };
}
```

Spawning a child process is fairly simple - you just call `fork()` and you match to one of the three possible conditions. It is worth noting here that Rust considers fork an unsafe operation but the code that follows doesn't have to be marked as one.

> This is actually a great feature of Rust that the match has to be exhaustive - that way we won't forget any possibilities and won't introduce some weird situation.

## Bring the ptrace

The next building block is the function that runs only in the child process.

```rust
// Code that runs only for child
fn run_child() {
    // Allows process to be traced
    ptrace::traceme().unwrap();

    // Disable ASLR for this process
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

    // Execute binary replacing
    Command::new("/home/carstein/sample").exec();

    exit(0);
}	
```

There are just three instructions here. First instructions tell the kernel that child is willing to become traceable. I know that I should handle errors better here, but all you need to know right now is that we `unwrap()` and result that this instruction returns and if we encounter any error we just panic.

Second instruction is obvious - we disable `ASLR` for the child process. 

Last thing is a handy function that handles process spawning and argument passing - `Command::new()`. Just bear in mind that while the `spawn()` method would fork and create a new process `exec()` will run the command in place replacing the current child process code.

## How to be a parent

Now to the biggest chunk of code here - the one that parents execute.

```rust
// Code that runs only for parent
fn run_parent(pid: Pid, breakpoints: &[u64]) {
    let mut saved_values = HashMap::new();

    // Placing breakpoints
    wait().unwrap();
    for addr in breakpoints.iter() {
        let orig = set_breakpoint(pid, *addr);
        saved_values.insert(*addr, orig);
    }
    ptrace::cont(pid, None).expect("Failed continue process");

    loop {
        match wait() {
            Ok(status) => {
                match status {
                    WaitStatus::Stopped(pid_t, sig_num) => {
                        match sig_num {
                            Signal::SIGTRAP => {
                                handle_sigstop(pid_t, &saved_values);
                            }
                            
                            Signal::SIGSEGV => {
                                let regs = ptrace::getregs(pid_t).unwrap();
                                println!("Segmentation fault at 0x{:x}", regs.rip);
                                break
                            }
                            _ => {
                                println!("Some other signal - {}", sig_num);
                                break
                            }
                        }

                    },
                    WaitStatus::Exited(pid, exit_status) => {
                        println!("Process with pid: {} exited with status {}", 
                        					pid, exit_status);
                        break;
                    },

                    _ => {
                        println!("Received status: {:?}", status);
                        ptrace::cont(pid, None).expect("Failed to deliver signal");
                    }
                } 
            }

            Err(err) => {
                println!("Some kind of error - {:?}",err);
            
            },
        }
    }
}
```

We need to explain three major parts of the code. At the very beginning we `wait()` for the child process to inform us that it just was loaded and is ready to be traced. We use this opportunity to place some breakpoints - one to be specific. How to place breakpoints we will cover later on.

Once the breakpoints are in place we can instruct the child (via `ptrace::cont()`) to continue execution until another interruption. 

> It is worth noting that there are other ways to continue the process. Two most popular is a single-stepping via `ptrace::step()` or until next syscall via `ptrace::syscall()`.

Next we enter a loop where we wait for the child process to change its state. Once a change occurs we check via `match status` what was the nature of the transition and react accordingly - if the child process is stopped we check why. In case of process that exited - we break the loop and terminate the parent as well. For simplicity I've decided not to implement all possible states.

## How to handle your child

When the child process stops the `WaitStatus` is kind enough to inform us what exact signal caused that and we handle each case accordingly with an inner match statement. 

> I don't know the Rust pattern matching statement well enough but I have a feeling that code can be probably simplified to be less nested.

Code bellow handles special case where we actually hit the breakpoint we set and we want to handle it properly.

```rust
fn handle_sigstop(pid: Pid, saved_values: &HashMap<u64, i64>) {
    let mut regs = ptrace::getregs(pid).unwrap();
    println!("Hit breakpoint at 0x{:x}", regs.rip - 1);

    match saved_values.get(&(regs.rip - 1)) {
        Some(orig) => {
            restore_breakpoint(pid, regs.rip - 1, *orig);

            // rewind rip
            regs.rip -= 1;
            ptrace::setregs(pid, regs).expect("Error rewinding RIP");

        }
        _ => print!("Nothing saved here"),
    }

    ptrace::cont(pid, None).expect("Restoring breakpoint failed");

}
```

In here we compare if the stop occurred in the place where we previously put our breakpoint. If that is the case we remove it by using the original instruction opcodes and rewind instruction pointer by one to continue execution.

## Placing breakpoints for lack of fun and profit

Placing and restoring breakpoints is covered by two separate functions. 

```rust
fn set_breakpoint(pid: Pid, addr: u64) -> i64 {
    // Read 8 bytes from the process memory
    let value = ptrace::read(pid, addr as *mut c_void).unwrap() as u64;

    // Insert breakpoint by write new values
    let bp = (value & (u64::MAX ^ 0xFF)) | 0xCC;

    unsafe {
        ptrace::write(pid, addr as *mut c_void, bp as *mut c_void).unwrap();
    }

    // Return original bytecode
    value
}
```

To insert a breakpoint we are using `ptrace` to read the 8 bytes of instruction opcodes and replace the first one with 0xCC. Later on we write back the modified bytecode and pass the original one to the calling function for saving.

> If you are looking for explanation how software breakpoints work please read my previous blog posts. [^1]

Removing the breakpoint is even easier.

```rust
fn restore_breakpoint(pid: Pid, addr: u64, orig_value: i64) {
    unsafe {
        // Restore original bytecode
        ptrace::write(pid, addr as *mut c_void, orig_value as *mut c_void).unwrap();
    }
}
```

The only tricky part in both cases is that `ptrace::read` and `ptrace::write` expect raw pointers denoted as `c_void` so we must use casting to obtain it. Be very careful what you do with them as Rust won't protect you when you try to shoot yourself in the foot.

## Summary

First contact with Rust was actually quite interesting. I had small problems translating some of the C concepts into it and the lack of proper documentation wasn't helping but in the end I enjoyed it very much. 

The best feature so far is the fact that return types carry much more information than in C so you don't have to use weird macros to extract exact status. Also, in Rust you can use matching and that also helps to write cleaner code.

#### Update
Full code is available on [github](https://gist.github.com/carstein/6f4a4fdf04ec002d5494a11d2cf525c7).
