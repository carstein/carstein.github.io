---
layout: post
title: "Build simple fuzzer"
subtitle: "part 2"
date: 2020-04-25
category: "Fuzzing"
tags:
- Fuzzing
---



In the [previous](https://carstein.github.io/2020/04/18/writing-simple-fuzzer-1.html) part of this mini-series we've implemented a very simple fuzzer.  As the main idea behind it is  being an exercise therefore I don't think it is capable of finding bugs in complex targets. Main reason for that is our mutation strategy. One we are using right now is completely random and lacks any feedback loop to tell us if the changes we are making to an original file are meaningful. In later parts we will try to do something about that but right now let's talk about some administrative issues first.

Code we wrote in the previous part is not complete but can be easily put together just joining snippets and adding necessary imports. In this part however code changes won't be implemented in a linear way making following the whole picture bit more difficult. To help you with that I've published  the whole program on [github](https://github.com/carstein/vsf) so you can follow the code in relation to the complete work.

# Improved architecture

Original architecture of the fuzzer was sufficient for the early phase but as we move forward it will quickly become a hindrance. Our first goal is to address some of the shortcomings without overengineering the application.

I've decided to focus on three separate things. First one is going to be support for runtime flags and global configuration file.

```python
config = {
  'file': 'mutated.jpg', # name of the target file
  'target': '',     # Location of program to execute
  'corpus': '',     # Initial corpus of files to mutate
  'rounds': 100000,  # How many fuzz iterations to run
  'seed': None,       # Seed for PRNG
}

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--target", help = "target program", 
      required=True)
  parser.add_argument("-c", "--corpus", help = "corpus of files",
      required=True)
  parser.add_argument("-r", "--rounds", help = "number of rounds", 
      required=False)
  parser.add_argument("-s", "--seed", help = "seed for PRNG", 
      required=False)
  create_config(parser.parse_args())
```

This change allowed us to get rid of many hardcoded paths, names and values.

Next change is allowing the fuzzer to consume either a single file or a directory of files.

```python
def get_corpus(path):
  corpus = []

  if os.path.isfile(path):
    with open(path, "rb") as fh:
      corpus.append(bytearray(fh.read()))
  elif os.path.isdir(path):
    for file in os.listdir(path):
      if os.path.isfile(file):
        with open(file, "rb") as fh:
          corpus.append(bytearray(fh.read()))

  return corpus
```

Again, this change alone does not offer us immediate benefits but will allow us to consume a whole corpus of files later on. That will be important when we finally implement some coverage measuring routines.

Last change, pretty cosmetic one to be honest is better handling of `ptrace` events.

```python
def execute_fuzz(dbg, data, counter):
  cmd = [config['target'], config['file']]
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  event = dbg.waitProcessEvent()
  
  if event.signum == signal.SIGSEGV:
    proc.detach()
    with open("../crashes/crash.{}.jpg".format(counter), "wb+") as fh:
      fh.write(data)
  else:
    proc.detach()
```

All those changes so far does not alter the functionality of the fuzzer. We will be moving to more significant improvements in due course.

# Repeatable randomness

Randomness is great. Our whole tool relies on random changes to the files. The key is knowing when there is just too much of it. For example sometimes we would like to be able to run exactly the same fuzz job you just ran previously. Why? Well, think about it as a debugging feature for now.

We are using a python library called [random](https://docs.python.org/3/library/random.html). If you read the documentation carefully you will realize it is based on Pseudo Random Number Generator (*PRNG*). It wouldn't be secure to use it if for example you want to generate cryptographic keys but is totally fine for our little project. That also means that such generator has a state that we can fetch or set. State however is slightly too big for us. We would have to serialize it to file and store on a disk. Later on we would have to read and deserialize it if we want to load it. Not very handy.

There is however a simpler method we can use. One of the characteristics of *PRNG* is that for the same seed value it will generate the same initial state.

```python
  # Seed the PRNG
  if config['seed']:
    initial_seed = config['seed']
  else:
    initial_seed = os.urandom(24)
    
  random.seed(initial_seed)
  print("Initial seed: {}".format(base64.b64encode(initial_seed).decode('utf-8')))
```

When our fuzz job starts we fetch random 24 bytes and use it as a seed. That way when we want to restore our state we will simply use the same seed value passed via runtime parameter. The only limitation of this approach is inability to stop the fuzz job in the middle and expecting the program to pick up from there upon the next run. Right now this is not a big deal and later on, as we implement our feedback loop it most likely won't matter at all.

# Unique crashes

Despite aforementioned limitations the fuzzer we originally wrote was able to trigger some crashes in our target Exif parser.  Actually it triggered way too many (over 7000) for us to analyze by hand. To make our triaging effort easier we will record only unique crashes instead of all of them. 

The core work will happen in `execute_fuzz()` - upon capturing `SIGSEGV` signal we record the value of the instruction pointer and associate it with the data that caused the crash.

```python
  if event.signum == signal.SIGSEGV:
    crash_ip = proc.getInstrPointer()
    if crash_ip not in crashes:
      crashes[crash_ip] = data
    proc.detach()
  else:
    proc.detach()
```

Sadly this doesn't work as expected. In the test run our fuzzer still recorded a lot of crashes. While those crashes are triggered at different addresses they seem to be caused by the same few instructions. Mechanism to blame here is of course `ASLR`.

We can solve this in three different ways. First method is to globally [disable](https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/) the `ASLR` for the whole system. That would work, but this is not the most elegant solution. Second method is to disable `ASLR` just for our process. After all, `gdb` can do it, why can't we? Unfortunately after lengthy digging I found it to be difficult if not outright impossible - we would have to call [personality](http://man7.org/linux/man-pages/man2/personality.2.html) syscall with `ADDR_NO_RANDOMIZE` flag before creating our child process to set up a proper execution domain. I can't see if python even supports that natively (without cpython) and ptrace library does not support that for sure, so let's try something different.

Last method is to just get a memory mappings of all program segments and use the base address of a code segment to calculate the absolute address of given functions.

```python
def absolute_address(ip, mappings):
  for mapping in mappings:
    if ip in mapping:
      return ip-mapping.start

def execute_fuzz(dbg, data, counter):
  cmd = [config['target'], config['file']]
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  event = dbg.waitProcessEvent()
  
  if event.signum == signal.SIGSEGV:
    crash_ip = absolute_address(proc.getInstrPointer(), proc.readMappings())
    if crash_ip not in crashes:
      crashes[crash_ip] = data
    proc.detach()
  else:
    proc.detach()
```

That works perfectly and generated only 8 unique crashes for our 100 000 rounds of mutation run. One caveat worth mentioning - the unique address we have obtained here won't actually point to the relevant instruction if you load target binary into your favorite disassembler (read - [Binary Ninja](https://binary.ninja/)). It is actually an offset into the `.text` section.

There is one potential issue with this simplistic approach. We are only going to keep one mutated data that triggered crash per given instruction that caused a segmentation fault. That might cause throwing out some perfectly good samples that triggered a crash in a bit different way. In effect we will have less samples to work with when it comes to debugging the program. I would however say that as long as we have a repeatable way of causing a given crash we have enough materials  to work with. 

# Future plans

I'm sure many of you expected more substantial changes to the fuzzer in this part. I understand that but please, do not despair. In the next part we will actually implement something more interesting - simple coverage measuring support. With that in place we can embark on even more ambitious adventures - genetic algorithm that will try to gradually select and mutate our samples to discover new crashes in yet unexplored parts of the program. Well, at least that is the plan for two parts. Later - we will see.

# References
 - Code for this part is available [here](https://github.com/carstein/vsf/releases/tag/v2)
 - Next part of the series is available [here](https://carstein.github.io/2020/05/02/writing-simple-fuzzer-3.html)