---
layout: post
title: "Grumpy Unicorn"
date: 2019-01-08
category: "Enginering"
tags:
- Unicorn
---

# Intro
Last few evenings I've spent playing with Unicorn Engine. Well, last few is a figure of speech here, as I was planing to write this text long time ago.
Anyhow, I just sit down to learn it bit more because I never really had a chance to develop better understanding and flow when it comes to this engine. 
In the end I've solved three optimization challenges and one obfuscation problem. I've also read some code written by other people ([hi gynvael](https://gynvael.coldwind.pl/?blog=1)). That does not make me an expert. Far from it. I, however learned something about it and I'm ready to complain.

# What is wrong with the engine,
Ultimately there is nothing wrong - engine works well (minus some weird quirks in interpreting some instructions, but if I remember correctly this should be attributed to QEMU).
People I've talked about comaplained about speed of execution, but in my cases it wasn't an important factor. What is more I haven't done any proper benchmarking, so I really don't have an informed opinion. Well, to be honest I see one place where execution slows down, but this is just an assumption. More of that later.

So, why this section even mentiones wrongness in the first place? Well, because there is a lot of wrong (in my opinion) in what API offers, how it works and how some things are structured. I'm not even going to start about documentation, because at least there are some code samples covering wide array of functionality that one can read. Still, proper documentation like for example one provided by [Binary Ninja](https://api.binary.ninja). would be nice.

## Superflous const naming
I'm not a big fan of typical style of imports where you pollute main namespace with all possible functions and classes like `from unicorn import all`.
Style I'm accustomed to the most comes from our [python styleguide](http://http://google.github.io/styleguide/pyguide.html), therefore if there is no proper module nesting I can always do `import unicorn` and when creating classes etc. I know where everything comes from.
Now, what I like about Unicorn is that constants have their own namespace. Even better, every architecture has their own namespace for const. And while they do, why oh why are they named with architecture prefix. Let me explain with this tiny code sample:

```python
import unicorn as un
import unicorn.x86_const as const
...
engine.reg_write(const.UC_X86_REG_RAX, ret_rax)
...
```
So, I've imported `x86_const` - I know that RAX register constant comes from Unicorn and from x86_const. I don't wan to write `UC_X86_REG_RAX` every time I want to access it.
I know this is just a tiny inconvinience and pretty much after typing it once any reasonable editor will complete it for you but still, this can be improved.


## Setup phase
When you are starting new emulation project you pretty much every time write exactly the same code:
```python
engine = un.Uc(un.UC_ARCH_X86, un.UC_MODE_32)

# Setup Code section
engine.mem_map(BASE, SIZE)

# Setup stack
engine.mem_map(STACK_ADDR, SIZE)
engine.reg_write(const.UC_X86_REG_ESP, STACK_ADDR + (SIZE/2))
engine.reg_write(const.UC_X86_REG_EBP, STACK_ADDR + (SIZE/2))

# Copy code
engine.mem_write(BASE, read_prog(sys.argv[1]))

# start
engine.emu_start(START, STOP)
```

All values like `BASE`, `SIZE`, `START` and `STOP` you have to retrieve manually by reading the header either via `readelf` or throwing given binary into your reverse engineering platform of choice.
This is tedious and I would really love some nice helper functions. It can be either high level like `load_elf()` or some medium level shortcut methods of Uc engine like `setup_stack(bottom, top)`. 

Another thing that really annoys me is how sometimes we need to skip certain instructions, because either they are making a call to a shared library (that we obviously have not loaded) or perform some IO operations. Typical code doing such task looks like this:
```python
skip_list = [
    0x40058A,   # call _printf
    ]
  
if address in skip_list:
  engine.reg_write(const.UC_X86_REG_EIP, address+size)
```
Not only you have to maintain a list of instructions to skip but also you have to manually adjust instruction pointer. First problem is hard to solve automatically, because engine might not know what exact instructions we want to skip, but manual adjustment of register is just ugly. I would love to have this as a core functionality.

## Hooks.
The worst thing in my personal opinion is how we are forced to use hooks. For every type of hook you define one global callback function. One.
Now, let's say you want to do three different operations in three distinc addresses - of course we all know how this is going to look in the code - tree of ifs.
Typical example of this situation we can for example observe in Unicorn [tutorial](http://eternal.red/2018/unicorn-engine-tutorial/) by Eternal Red:
```python
if address in skip_list:
  engine.reg_write(const.UC_X86_REG_RIP, address+size)
elif address == 0x400560:
  c = engine.reg_read(const.UC_X86_REG_RDI)
  key.append(chr(c))
  engine.reg_write(const.UC_X86_REG_RIP, address+size)
elif address == FIB_START:
  arg0 = engine.reg_read(const.UC_X86_REG_RDI)
  rsi = engine.reg_read(const.UC_X86_REG_RSI)
  arg1 = u32(engine.mem_read(rsi, 4))

  if (arg0, arg1) in know_vals:
    ret_rax, ret_ref = know_vals[(arg0, arg1)]
    engine.reg_write(const.UC_X86_REG_RAX, ret_rax)
    engine.mem_write(rsi, p32(ret_ref))
    engine.reg_write(const.UC_X86_REG_RIP, 0x4006F1)
  else:
    stack.append((arg0, arg1, rsi))
```
Same of course goes for `UC_HOOK_MEM_*`. It also means, that your python function gets called for every instruction you execute - I can only imagine what impact it has on performance. This mess begs for a per address hooks (but truth be told, I don't know QEMU internals enough to say if this is even possible).


## Misc
There are two more problems that you need to solve during typical emulation process and you have to do it *manually*. 

First, reading string from memory - there is no shortcut for that. Basically you need to read byte by byte in a loop until NULL value.
Second - shortcut for read value pointed by reg like `[eax]` that requires writing two instructions:
```python
rsi = engine.reg_read(const.UC_X86_REG_RSI)
val = u32(engine.mem_read(rsi, 4))
```

## Summary
In the end - Unicorn seems to be a nice emulation engine. Fairly approachable and easy to use. Don't let the old man ranting disdain you.
All I wish for is just better API so I don't have to write the same snippets of code again and again. It looks like I will eventually have to write those shortcuts functions myself.

