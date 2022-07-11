---
layout: post
title: "Binary Ninja Recipes"
date: 2017-11-29
tags:
- Binary Ninja
---
What is the value of a blog if you don't post something from time to time. But what to publish when you only recognize two kinds of knowledge: something you know, therefore it is trivial and something you don't know, therefore you shouldn't be writing about that? Well, today is the time for some trivial knowledge - Binary Ninja recipes.

# Problem 1: how to develop plugins
I was trying to find an optimal way to structure my development environment for plugins for some time. First - for Binary Ninja to discover and run one it must be located in `~/.binaryninja/plugins/` directory (I'm skipping headless plugins that you can just run from anywhere, given your `PYTHONPATH` is set correctly). Obvious solution is to edit it directly there, but somehow I was seeing this solution as inelegant. At first, I was editing files in my project directory and copying it manually, but after few times it became tedious. So, in the next step I've developed universal shell script that was taking plugin files and deploying it to relevant directory in binary ninja tree. That however had one tiny flaw - I had to remember to execute the deployment. Multiple times in my flow I was restarting Binary Ninja, opening binary file and executing plugin only to realize I'm still running old version of it
.
My next try was with Binary Ninja internal plugin system - it can fetch code from remote git repository and just make it run locally. But still, it was too complicated for a simple problem I was facing. I've asked good people on Binary Ninja Slack channel and I've adjusted my workflow basing it on few suggestions.

I primarily use git during my development, so I can later push things to github.com. I keep two main branches - stable and dev. Now, in addition to that I basically soft link my project directory under binary ninja plugin directory. When I want to develop new feature I switch to dev branch and I get instant deployment for free and when I just want to use it I checkout stable version. (I told you this is going to be trivial).

# Problem 2: Binary Reader
Now, something more technical. Let's say you want, for some reason, to read/scan whole binary you've loaded into binary ninja; to, for example, find some pattern. My initial idea was to do it like this:
```python
# bv stands for BinaryView
for addr in range(bv.start, bv.end):
  b = bv.read(addr, 1)
```

This approach has few flaws. First of all, return type is string, so if for example you want to read 4 bytes and compare it against value like `0x41414141` you need to unpack it into correct type. Second one is you can't move forward and backward with ease. I've decided that it would be better to use Binary Reader, so I wrote this:

```python

br = bn.BinaryReader(bv)
 
while not br.eof:
  f_byte = br.read8()
```

In theory that should scan every byte of a binary, mapped or not. Every `read8()` call move internal read offset by one byte and return value corresponds to relevant function being called. There was one small problem with that code - it ended up with infinite loop. Took me while to understand what is going on. Basically, if a read steps out of mapped segment and return null value it stops moving internal offset, hence the infinite loop. Improved version of the code now looks roughly like this:

```python
br = bn.BinaryReader(bv)
 
while not br.eof:
  if bv.is_valid_offset(br.offset):
    f_byte = br.read8()
  else:
    br.seek_relative(1)
```

That works as expected.

From now on I will try to write short pieces of "How I do things" style posts, especially about Binary Ninja. I've even started drafting something I refuse to call book, but if I have enough material related to writing Binary Ninja plugins, who knows. Let me know what do you think about all of this! Next time I will try to write some more about Binary Ninja plugin repository management.