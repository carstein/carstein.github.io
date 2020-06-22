---
layout: post
title: "Build simple fuzzer - part 1"
date: 2020-04-18
---

# Background

We are locked in our houses now and it is not easy. In situations like this it is important to have a pet project on the side so you don't get crazy. Well, after seeing what some people post on twitter I think it is actually too late for some. Anyway, for the remaining few I've decided to start a short series that will focus on writing a simple fuzzer from scratch.

I think every security person should at some point write one. Not to really use it, no. That would be crazy considering how [many](https://lcamtuf.coredump.cx/afl/) [great](https://github.com/google/honggfuzz) [fuzzers](https://llvm.org/docs/LibFuzzer.html) are out there. But I'm a strong believer in the idea that if you really want to understand something you should try to disassemble/recreate it.

To be quite honest with you it wasn't an original idea. Some time ago [h0mbre](https://twitter.com/h0mbre_) wrote an article '[Fuzzing like a Caveman](https://h0mbre.github.io/Fuzzing-Like-A-Caveman/#)' followed up by another one titled '[Improving Performance](https://h0mbre.github.io/Fuzzing-Like-a-Caveman-2/)'. I really applauded him for his effort but while reading the code I've realized I can probably improve and expand his work a bit. Before we proceed any further I suggest you check original articles first.

# Caveats

First of all, we are learning here and this fuzzer is in no way going to be a proper tool used against real targets (at least not initially). This is why we are going to code it in python. For real tools we should have picked something way closer to the metal - language that compile to a native code. Most of the fuzzers used professionally are written in C/C++ and some [cool kids](<https://twitter.com/gamozolabs>) use Rust, but almost nobody uses python. Fuzzing is primarily about how many executions per second you can squeeze out and use of interpreted language incurs many speed penalties.

Second important thing is to pick a right target - we are going to use the [exif library](https://github.com/mkttanabe/exif) mentioned in h0mbre's article because it was coded many years ago and will most likely spew crashes like there is no tomorrow. There is nothing worse than picking a target that might be actually well written. You will spend the rest of your day wondering if you suck at coding/fuzzing or maybe there are no crashes to be found. Remember - we are learning, we want some quick results.

# Main parts of fuzzer

The premise of fuzzing is deceptively simple - you feed random data to a program and see if it crashed. Then you change the data a little bit and feed it to a program again. And again. And again. So essentially it is doing exactly the same thing over and over again expecting different outcomes. [Like insanity](https://www.youtube.com/watch?v=zEWJ-JgVS7Q). Before we move further there is one golden rule of fuzzing that you have to remember till the end of your days. It's like the equivalent of Heisenberg principle or Schroedinger paradox - an observed fuzzer never crashes.

Back to the general architecture - every fuzzer has at least two main components - mutation and execution engine. This is roughly how I've initially implemented it (and remember, it heavily borrows from 'Fuzzing like Cavemen' article):

```python
def main():
  if len(sys.argv) < 2:
    print('Usage: {} <valid_jpg>'.format(sys.argv[0]))
  else:
    filename = sys.argv[1]
    orig_data = get_bytes(filename)
    dbg = debugger.PtraceDebugger()

    counter = 0
    while counter < 100000:
      data = orig_data[:]
      mutated_data = mutate(data)
      create_new(mutated_data)
      execute_fuzz(dbg, mutated_data, counter)

      if counter % 100 == 0:
        print('Counter: {}\r'.format(counter),file=sys.stderr, end='')
      
      counter += 1 

    dbg.quit()
```

Presented main function can be divided into two parts - setup phase and fuzz loop. 

Setup phase should ideally be executed only once per fuzz job so it's an ideal place for all performance heavy operations - initialization of necessary components, reading configuration files etc. Our fuzzer actually doesn't have that much of a setup to speak of. We only read the original file sample (more about it later) and set up a debugger (again, more about it later).

Fuzz loop is the section of the code that will be executed thousands (or possibly millions) of times, therefore it is paramount  to put only necessary code there. In our case we do two important things in the loop - we mutate the data and run the target program. There is some extra stuff that we can probably remove (like printing out the counter) but let's leave it for now.

# Mutation engine

The most important part of our fuzzer is the mutation engine. This is also the part where I saw the biggest opportunity for improvement (especially around performance). Another important advice for you - when you are fuzzing you always should start with a valid data sample and mutate it. If you start with random data there is a good chance your fuzzer will spend most of the cycles producing files that target program will immediately discard because the first two magic bytes do not match expected value.

In our case we are starting with a known good jpeg file that contains valid exif data - [Canon_40D.jpg](https://github.com/ianare/exif-samples/blob/master/jpg/Canon_40D.jpg). We read it via `get_bytes()` function, turn into a bytearray and feed to function below:

```python
def mutate(data):
  flips = int((len(data)-4) * FLIP_RATIO)
  flip_indexes = random.choices(range(2, (len(data) - 6)), k=flips)

  methods = [0,1]
  
  for idx in flip_indexes:
    method = random.choice(methods)

    if method == 0:
      data[idx] = bit_flip(data[idx])
    else:
      magic(data, idx)

  return data
```

First two lines are responsible for selecting how many and which bytes in our file we are going to modify. With `FLIP_RATIO` set to 1% we are roughly going to modify a given file in 80 places. For now this is completely arbitrary value but in future generations of fuzzer we will try to determine best value via some experimentation. Another thing worth noticing is that we want to avoid overwriting the first and last two bytes of a file (as jpeg format has some magic values there). Overwriting those magic values might result in a program discarding our file prematurely.

In the main loop of the function we select one method we want to apply for a given byte(s) - either bit flip or magic value. Let's cover bit flip first as it is very simple:

```python
def bit_flip(byte):
  return byte ^ random.choice([1, 2, 4, 8, 16, 32, 64, 128])
```

I don't even think it requires explaining, but let's do it for posterity. Array we are picking the one value from contains all possible values of a byte with only one bit 'lit'.  So, in short, we are selecting a single bit to flip in target value. Operation denoted by `^` is of course `XOR`.

Magic values are only a bit more complicated. I'm going to skip the whole theory behind them but the short version is - those values are usually at the edge of maximum or minimum sizes for various types of integers. Being on the edge makes them very susceptible to off/under by one bugs caused by unsafe arithmetic operations.

```python
MAGIC_VALS = [
  [0xFF],
  [0x7F],
  [0x00],
  [0xFF, 0xFF], # 0xFFFF
  [0x00, 0x00], # 0x0000
  [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
  [0x00, 0x00, 0x00, 0x00], # 0x80000000
  [0x00, 0x00, 0x00, 0x80], # 0x80000000
  [0x00, 0x00, 0x00, 0x40], # 0x40000000
  [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

def magic(data, idx):
  picked_magic = random.choice(MAGIC_VALS)

  offset = 0
  for m in picked_magic:
    data[idx + offset] = m
    offset += 1
```

When implementing magic numbers you have to decide if you want to manually split your values into bytes (hardcoding little endianess) or write smarter functions using binary shifts. I'm lazy so I've picked up the former. Again, at least for now.

This absolutely does not exhaust the topic of mutation strategies as there are many more to pick from. Right now we have only implemented two and a major shortcoming of our mutator is the fact that the file we feed to the program never changes in length. Over time we will improve that.

# Program execution

With our initial data mutated it is time to run the target program and see if by any chance it crashes. Most typical approach is to use some form of `execv()/Popen()/run()` function. This would force us to read the program/shell output and parse it looking for words like 'Segmentation Fault' or checking the return code. I have to say I didn't like the idea much as I was always a big proponent of well structured outputs. In consequence I've decided to run our program under `ptrace`.

```python
def execute_fuzz(dbg, data, counter):
  cmd = ['exif/exif', 'data/mutated.jpg']
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  try:
    sig = dbg.waitSignals()
  except:
    return
  
  if sig.signum == signal.SIGSEGV:
    proc.detach()
    with open("crashes/crash.{}.jpg".format(counter), "wb+") as fh:
      fh.write(data)
```

This is actually the first time I've used [python-ptrace](https://github.com/vstinner/python-ptrace) so I'm not entirely sure I'm doing everything correctly. The basic principle behind this code is that we just create a child process and start it under the debugger so we can watch for signals like `SIGSEGV`. In case we receive one we save the file that caused the crash with a unique name for further analysis. If a program finishes without any signal `waitSignals` just raises an exception and we stop this run.

Currently this method does not offer us much more than `Popen()` would. In time however I intend to build more functionality upon it.

# What should come next

When I ran my fuzzer I got 7810 crashes after only 100 000 iterations (by the way, it took only 6 minutes and 39 seconds). Given our unsophisticated mutation method and absolute lack of coverage measurements most likely many of them have exactly the same reason. In the next part of this series we will implement method to better determine uniqueness of a crash as well as other improvements around randomness.

Right now our fuzzer is solely based on luck - it might modify the right bytes but it very well might not. In case of easy target like our exif library it clearly is enough, but will most likely fall short for harder ones. In part three I will try to implement some basic code coverage measurement to see if given changes in the sample file lead to more code being covered by our fuzzer.

# References
 - Code for this part is available [here](https://github.com/carstein/vsf/releases/tag/v1)
 - Next part of the series is available [here](https://carstein.github.io/2020/04/25/writing-simple-fuzzer-2.html) 

