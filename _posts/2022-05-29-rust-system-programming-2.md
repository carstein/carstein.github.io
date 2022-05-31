---
layout: post
title: "System programming in Rust, take 2"
date: 2022-05-29
---

A friend of mine once said - *"If you are not embarrassed by the work you've done two years ago, you are getting complacent"*. Well, I'm certainly embarrassed. It does not mean I'm not getting complacent but the embarrassment is there.

Some of you might ask what I am so embarrassed about? Is it because I write to rarely? Or maybe because I still haven't finished the *"Writing your own fuzzer"* series? Well, yes and yes, but the core reason is different. Recently someone has reached out to me to ask some questions about one of the previous posts - *["System programming in Rust"](https://carstein.github.io/2020/11/18/ptrace-rust.html)*. Question was fairly simple but to answer it I had to re-read the whole post again. Let me tell you - I wasn't happy about it. Code quality and structure wasn't great. So, today I've decided to rewrite it as well as I can. Let's see if I need to rewrite it again in two years.

### Code structure

Before we begin let me explain a little bit more about my approach to code snippets. Reason behind it is one of the question I was asked hinted about this not being very clear. Often people expect, especially in case of introductory materials to be able to copy & paste the snippet of code and run it on their machine. Sadly, in case of many of my posts this is difficult as the snippets are not fully functioning programms. If I want them to be I would have to, every time publish one with all the functions, imports and structures or make a detailed explanation where in the code a given snippet should be placed inserted. 

My approach will remain bit different - snippets are merely to illustrate the concept I'm explaining in a given section and they won't be a fully functioning programs. However, at the end of every post I will try to publish a link that will take you all to either the full github repository at least a github gist so you can play with the code on your own.


### Running programs

We can start our journey with the piece of code that wrote 2 years ago that I'm least proud of - running another program.

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

// Code that runs only for child
fn run_child() {
    // Allows process to be traced
    ptrace::traceme().unwrap();

    // Disable ASLR for this process
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

    // Execute binary replacing the currently running code
    Command::new("/home/carstein/sample").exec();

    exit(0);
}
```

There are several problem with it. First of all, it's long, convoluted and while it uses the `Command` module it does not take advantage of all the possibilities it offers. On top of that we are manually calling `fork()` like it is some kind of C with borrow checker. We can do way better than that - as demonstrated by the code bellow.

```rust
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

fn main() {
    let child = unsafe {Command::new("/home/carstein/sample")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .pre_exec(|| {
            personality(linux_personality::ADDR_NO_RANDOMIZE)
            .expect("[!] cannot set personality");
            Ok(())
        })
        .spawn()
        .expect("[!] Failed to run process")
    };

    println!("Started process with PID: {:?}", child.id());
}
```

This one is much better in my opinion - we are taking the full advantage of `Command` features. Two most important ones are the `pre_exec()` and `spawn()` functions. The first one accepts closure and executes all the enclosed instructions before the main code is run while the second one is responsible for running the target binary as a child process. Lack of knowledge about the `pre_exec()` is precisely what drove me to this monstrosity that you've seen in the previous snippet. 

There is one additional thing that require explaining, especially if you are planning to do more system programming. You might be wondering why we are importing `std::os::unix::process::CommandExt;` while it doesn't look like we are making any use of it. Reason is fairly simple - `std::process::Command` contains only basic functionality that is available in all supported environments. If however you wish to use any OS-specific functionality like running the program with given `uid` or, in our case, execute some syscalls before the main function of the program starts you need to load a *library extension*.

### Inspecting the status

Let's say, that you would like to see what has happened with the program after you run it. You can of course check that by calling `child.wait()` and inspecting the exit code but that does not tell us much about various abnormal ways the program can terminate. Let's try using `waitpid()` instead.

```rust
    // this code goes after starting the process
    match waitpid(Pid::from_raw(child.id() as i32), None) {
        Ok(WaitStatus::Exited(pid, status)) => {
            println!("Program {} exited normally with code {}",pid, status);
        }
        Ok(WaitStatus::Signaled(pid, signal, core)) => {
            println!("Program {} was terminated by signal {} (core dumped: {})",
        pid, signal, core);
        }
        Ok(status) => println!("Status: {:?}", status),
        Err(err) => {
            println!("We've encountered some kind of error: {:?}", err);
        }
    }
```

Here, in addition to normal way that program can terminate we are also checking if maybe the reason for termination was some kind of signal like `SIGSEGV` or `SIGABRT`. For a full list of possible conditions you should check the [documentation](https://docs.rs/nix/latest/nix/sys/wait/enum.WaitStatus.html#variants) and I suggest you do that because you will need that for what comes next. 

Before we jump further - have you noticed difference to the code I wrote previously? The match directive does not need to reassemble a nested tree - it can be much flatter and that improves readability significantly.

### Tracing

The goal of the code, last time I wrote it was to be an instrumentation module for my fuzzer so there is no point deviating from this path now. First step is to enable process tracing and we can do it by adding one more instruction to our `pre_exec` block.

```rust
// Partial snippet of code that normally should be chained together
// with the Command::new
    .pre_exec(|| {
        ptrace::traceme()
        .expect("[!] cannot trace process");
        personality(linux_personality::ADDR_NO_RANDOMIZE)
        .expect("[!] cannot set personality");
        Ok(())
    })
```

### Setting a breakpoint

If you try to run this code you will notice, that suddenly our `waitpid()` report a `SIGTAP`  and we need to handle this explicitly - mostly because there will be a lot of work to do.

```rust
// This is part of the waitpid() match instruction
        Ok(WaitStatus::Stopped(pid, signal)) => {
            println!("Program {} received {} event", pid, signal);
            handle_sigstop(pid);
        }

// This is a separate function that should be defined outside of main
fn handle_sigstop(pid: Pid) {
    let regs = ptrace::getregs(pid).unwrap();
    println!("Hit breakpoint at 0x{:x}", regs.rip);
}
```

Now, knowing that indeed we are attached to a running process we can finally start setting some breakpoints. A function to do that is fairly simple:

```rust
fn set_breakpoint(pid: Pid, addr: u64) -> u64 {
  // Read 8 bytes from the process memory
  let value = ptrace::read(pid, (addr) as *mut c_void).unwrap() as u64;

  // Insert breakpoint by write new values
  let bp = (value & (u64::MAX ^ 0xFF)) | 0xCC;

  unsafe {
      ptrace::write(pid, addr as *mut c_void, bp as *mut c_void).unwrap();
  }

  // Return original bytecode
  value
}
```

As I've previously explained - in order to set a breakpoint at a given address we need to `ptrace::read` 8 bytes from the memory, set first byte (little endian) to `0xCC` and write to process memory it back using `ptrace::write`. The original bytecode is returned back to the caller so we can restore it later, upon handling given breakpoint.

It goes without saying that this type of *open heart surgery* is fairly dangerous and one need to be extra careful doing that as Rust is not very likely to save us from various mistakes. 

> If you are interested how exactly software breakpoints work you can read more about it in *[Build simple fuzzer - part 4](https://carstein.github.io/2020/05/21/writing-simple-fuzzer-4.html)*

As we've already mentioned - we need to clear the breakpoint after we hit it - for that we have a function called `remove_breakpoint()`

```rust
fn remove_breakpoint(pid: Pid, addr: u64, orig_value: u64) {
    unsafe {
        // Restore original bytecode
        ptrace::write(pid, addr as *mut c_void, orig_value as *mut c_void).unwrap();
    }
}
```

### Joining it together

There is really no point to repeat all I've written about handling breakpoints as I've already done it in *[Build simple fuzzer - part 5](https://carstein.github.io/2021/03/13/build-your-own-fuzzer-5.html)* but for posterity the main function handling it all together is just and expanded `handle_sigstop()`. 

```rust
fn handle_sigstop(pid: Pid, saved_values: &HashMap<u64, u64>) {
    let mut regs = ptrace::getregs(pid).unwrap();
    println!("Hit breakpoint at 0x{:x}", regs.rip - 1);

    match saved_values.get(&(regs.rip - 1)) {
        Some(orig) => {
            restore_breakpoint(pid, regs.rip - 1, *orig);

            // rewind rip
            regs.rip -= 1;
            ptrace::setregs(pid, regs).expect("Error rewinding RIP");
        }
        None => print!("Nothing saved here"),
    }

    ptrace::cont(pid, None).expect("Restoring breakpoint failed");
}
```

### Conclusion

I hope that this post make up for the terrible quality of the previous one. When it comes to Rust (and quite frankly, any programming language) you really need that experience and reading other people code helps a lot (personally I've learned a lot from [Brandon Falk](https://twitter.com/gamozolabs)). I actually planning to write bit more about system programming because the more I do it the more antsy I get, especially around some of the libraries out there. Sometimes it feels like I'm writing a C with borrow checking on the side. Still, I'm planning to rant some more about that, but also to share some of the tips how to write safe wrappers around those low level concept.

As promised - you can see most of the functionality described above in my toy fuzzer [rfuss2](https://github.com/carstein/rfuss2).
