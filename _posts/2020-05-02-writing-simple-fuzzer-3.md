---
layout: post
title: "Build simple fuzzer - part 3"
date: 2020-05-02
tags:
- Fuzzing
---

Welcome to part three of my mini series about fuzzing.  I'm glad that so many of you find this content interesting enough to come back for more. This, more than anything encourages me to keep writing.

We've ended the [last part](https://carstein.github.io/2020/04/25/writing-simple-fuzzer-2.html) with a promise that we are going to work on a more intelligent approach to fuzzing. To keep content easily digestible I've decided to split the task into two separate articles. In the one you are reading right now we are going to cover the implementation of coverage tracing. Upcoming one will cover the topic of how this information can help to guide the fuzzing process to obtain better results.

We must begin with a bit of [theory](https://google.github.io/clusterfuzz/reference/coverage-guided-vs-blackbox/): *"Coverage guided fuzzing (also known as greybox fuzzing) uses program instrumentation to trace the code coverage reached by each input fed to a [fuzz target](https://google.github.io/clusterfuzz/reference/glossary/#fuzz-target). [Fuzzing engines](https://google.github.io/clusterfuzz/reference/glossary/#fuzzing-engine) use this information to make informed decisions about which inputs to mutate to maximize coverage."* As explained further in the linked doc this technique is good for deterministic targets with suitable tolerance for unstructured data. A good example of such is a parser for *jpeg* format. This matches the target we've initially selected. Be aware however that random mutations of highly structured inputs like programming languages will most likely fail to produce valid data. Consequently the depth of the fuzz run will suffer in effect.

I must confess that I haven't done much research how coverage tracing should actually look like and this is one big experiment. So, this is going to be a learning experience for all of us. Well, maybe excluding seasoned authors of fuzzing tools. Oh, one last thing - as always, latest iteration of the code can be found on [github](https://github.com/carstein/vsf).

# Measuring performance

Instrumentation inevitable comes with a cost. First victim is performance. I know that one worrying about performance shouldn't have picked python as a language of choice in the first place. Nevertheless we will try to keep up an appearance as lessons learned here will pay off when we finally rewrite it all to Rust.

Knowing about the sacrifices we are making it is still good to measure how much of the performance we are losing at each step. With that in mind I've decided to implement simple status that will tell us roughly how many iterations per second our fuzzer is able to execute. Expecting this to be an easy task I've started reading and coding some something simple. Somewhere mid-way, having a custom Threaded class that was spawning other objects at fixed time intervals and accounting for a time drift I caught a glimpse of myself in a window and started pondering about the meaning of life. Well, it wasn't that dramatic but surely I've left *'simple'* and drifted somewhere towards *'how do I pass values between threads'*. I've deleted that code and instead just wrote this:

```python
    start_time = time.time()
  	...
    # FUZZ LOOP HERE
    ...
    x = counter / (time.time()-start_time)
    print('-> {:.0f} exec/sec'.format(x))
```

Our naive way to measure the performance is to simply divide the number of iterations we run by the elapsed time. This is not the most sophisticated way of doing it and in the next stage we will have to implement it differently. Especially when we get rid of a fixed number of rounds and switch to continuous fuzzing. For now it will do.

On the topic of performance - if you are really interested how to profile your programs better read the documentation for two amazing python modules - [profile](https://docs.python.org/3/library/profile.html?highlight=cprofile) and [memory_profiler](https://pypi.org/project/memory-profiler/).

# Idea 1 - Single stepping

Having the means to see how much each approach is going to cost us we need to test some of the ideas.

There is one important concept I've skipped over before and it is coverage granularity. We can track executed functions, blocks or even instructions. For our fuzzer I've decided to keep resolution at function level but extending it to blocks should be that challenging. 

Only instrumentation that we have at our disposal right now is ptrace therefore it will remain a cornerstone of our approach. My initial idea was to single step through the code and inspect instructions as we go. That way, every encountered `call` would tell us that we are hitting the next function and every `ret` - that we are leaving it.

Looking in retrospect this approach would have had a serious flaw - we wouldn't even know what percentage of the program we've managed to cover. 

In the initial implementation to implement this idea I've only enabled single stepping - just to see how well it would perform. It was a disaster. We went from ~300 down to less than 1 exec/sec. That was even before I'd implemented any instruction disassembly. Clearly this was a dead end and a better approach was required.

Modern fuzzers like [AFL](<https://github.com/google/AFL>) do it by inserting instrumentation in a form of short function stubs right into the binary.  I didn't want to go this way because I wasn't sure we are ready to dive that deep into compiler internals. Instead, I've started thinking about `ptrace`.

# Idea 2 - Breakpoints

Idea for better approach came pretty quickly. We are going breakpoints at the beginning of every function. Our fuzzer is already capable of handling signals so adding bit of code to handle `SIGTRAP` is not a problem. As always - idea is simple but implementation got bit more convoluted.

## Generate function list

First problem to solve is knowing where exactly we need to put those breakpoints. This is actually not that complicated - just fire up your favorite disassembler, load your target binary and look for start address of identified functions. I wrote a small Binary Ninja script to automate that task:  

```python
def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-b', '--binary', help = 'binary to analyze', 
      required=True)
  args = parser.parse_args()

  bv = bn.BinaryViewType.get_view_of_file(args.binary)

  # select appropriate segment
  for s in bv.segments:
    if s.executable:
      base = s.start

  for func in bv.functions:
    # filter out the list of functions
    if func.symbol.type == bn.SymbolType.ImportedFunctionSymbol: continue
    if func.name in skip_func: continue
    
    print('0x{:x}'.format(func.start - base))
```

You might wonder why I have not integrated this functionality into the fuzzer itself. Reason is not of technical nature. Running Binary Ninja in headless mode requires a professional license. While it is worth every penny when you are working in any area of low level security I realize that probably many of you still don't have it. Personally I hate a situation where following some technical tutorial is impossible because you don't have certain paid tool. Taking it all into consideration I've design it in a way that my tool outputs a list of addresses that core fuzzer can just consume. You can most likely generate such list using a simple `objdump` and some `awk/sed`. If your [live](https://www.youtube.com/watch?v=GCWcftMJuDA) by *'It don't feel good until it hurts'* you can even use [Radare2](https://rada.re/n/).

There are two things about my script that I would like to explain in detail. Procedure of calculating the breakpoint address is one. We begin by locating the `.text` segment as this is where code is located. Start address of this segment will be the `base` that we subtract from the function start address. What we get in effect is an offset into the code segment for a given function. Why offset and not the main address? During the process of executing the binary the `.text` segment is loaded into a memory  under a virtual address and the nominal address taken from a file wouldn't do as any good. Offset however, when added to the start of proper memory area will allow us to put breakpoints squarely at the start of the function. 

Few paragraphs before I've mentioned that we want to trace the execution of each function. But do we really? In our script we filter out some we are not interested in. We are not going to track any libc functions as well as some setup functions. Full list of functions to skip is bellow.

```python
skip_func = ['__libc_csu_init', 
             '__libc_csu_fini', 
             '_fini',
             '__do_global_dtors_aux',
             '_start',
             '_init']
```



Admittedly I was inspired to do this function culling by [blog post](https://googleprojectzero.blogspot.com/2020/04/fuzzing-imageio.html) authored by my colleague. In my case I've decided to skip only a limited number of them but as you study your target better you might want to expand the list.

## Implementing trace

With a list of breakpoints loaded into fuzzer we can begin implementing breakpoint insertion and signal handling. I've decided to paste the complete function here to make it easier for the readers to track the relevant piece of code easier in relation to the whole.

```python
def execute_fuzz(dbg, data, counter, bpmap):
  trace = []
  cmd = [config['target'], config['file']]
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  base = get_base(proc.readMappings())

  # Inser breakpoints for tracing
  if bpmap:
    for offset in bpmap:
      proc.createBreakpoint(base + offset)
  
  while True:
    proc.cont()
    event = dbg.waitProcessEvent()
    
    if event.signum == signal.SIGSEGV:
      # getInstrPointer() always returns instruction + 1
      crash_ip = proc.getInstrPointer() - base - 1 
      if crash_ip not in crashes:
        crashes[crash_ip] = data
      proc.detach()
      break
    elif event.signum == signal.SIGTRAP:
      trace.append(proc.getInstrPointer() - base - 1)
    elif isinstance(event, debugger.ProcessExit):
      proc.detach()
      break
    else:
      print(event)
  
  # Program terminated
  return trace
```

Given that his function hasn't changed that significantly we are going to cover only the important parts. To insert the breakpoint correctly we need to know the base address of the memory area where our code is located. We get it by executing `get_base()` copied below.

```python
def get_base(vmmap):
  for m in vmmap:
    if 'x' in m.permissions and m.pathname.endswith(os.path.basename(config['target'])):
      return m.start
```

All it takes is loading all memory mappings and trying to find an executable one that pathname matches the target. That will also help us to deal with `ASLR` when tracking unique crashes.

Later on we simply iterate over the list of function offsets (named `bpmap`) and, after calculating the right address by adding base and function offset we insert a breakpoint there. Just like that:

```python
  if bpmap:
    for offset in bpmap:
      proc.createBreakpoint(base + offset)
```

When the debugger encounters the breakpoint it generates a `SIGTRAP` signal, so we need to add an additional branch to handle that. We do it by adding this branch to our signal handling routine.

```python
elif event.signum == signal.SIGTRAP:
  trace.append(proc.getInstrPointer() - base - 1)
```
Our coverage trace is fairly simple - we just record every function that we've executed during the current run. We will make some normalization of this trace later on. Quite frankly, after the run is done we just discard the whole trace as right now we don't have a good use for it. Whole apparatus to take advantage of it will come in the next part.

## Ideas for improvement

There are probably some better ways to handle instrumentation. We could do as [@5aelo](https://twitter.com/5aelo) did - modify the binary only once inserting the breakpoints manually. We can save some time in the execution loop that way, but I'm expecting some problems along the way. For example I would have to handle restoring the code as the program hits breakpoint from the shadow space manually. 

On top of that, before we have a feedback loop implemented I'm not sure our granularity is sufficient. We will run some tests later on and if needed, we are going to implement a block level coverage resolution.

# What's next?

Sadly, implementing our instrumentation caused some major performance hit. We went down from ~300  down to ~50 exec/sec. Looks like we just managed to slow down our fuzzer 6 times and gained nothing in return. 

As promised in the next part we will attempt to recover from that situation by completely changing our mutation strategy. This will turn our fuzzer into a coverage driven one with genetic algorithms deciding which mutated files to discard and which to keep for further mutation. I hope we can discover some new bugs with that approach.

# References
 - Code for this part is available [here](https://github.com/carstein/vsf/releases/tag/v3)
 - Next part of the series is available [here](https://carstein.github.io/2020/05/21/writing-simple-fuzzer-4.html)