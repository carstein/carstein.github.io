---
layout: post
title: "Annotate all the things"
date: 2017-02-21
tags:
- Binary Ninja
---
I don't do reverse engineering for a living but I still like to peek under the hood of binaries from time to time. Either because of testing, looking for bugs or just for fun. Problem is, that IDA Pro, de-facto standard tool for any Reverse Engineer is prohibitively expensive for most of the people. On top of that, licensing policy is very annoying and illogical. But enough about IDA Pro - let's talk about new contender on this field - [Binary Ninja](https://binary.ninja/).

I'm not going to repeat all the praises that this tool is receiving. Instead, you may for example read how you can use it to [automatically reverse 2000 binaries](https://blog.trailofbits.com/2016/06/03/2000-cuts-with-binary-ninja/) or maybe how the underlying [Low Level Instrumentation Language](https://blog.trailofbits.com/2017/01/31/breaking-down-binary-ninjas-low-level-il/) works. All in all platform looks very promising and I couldn't wait to try it after seeing it for the first time. Couple of months ago I was playing with the Beta and pretty much bought it first day it was released.

There is one tiny problem with Binary Ninja however - IDA Pro was here for years, therefore it is both feature rich and ecosystem around it is pretty robust. Binja still has a long way to go in this department - there are not that many useful plugins and some features are missing. One thing I've noticed for example is that while reversing basic libc functions and system calls are not annotated in any way. There is no prototype of them and arguments are not marked in any way. So instead of complaining I've decided to utilize available API and just fix that.

Let's start by defining a problem. For example we have a listing like this:
![before]({{site.url}}/assets/images/before.png){:class="center"}

Not terribly descriptive, right? Well, at least for strcpy() we roughly remember the prototype so we can quickly find where arguments are being pushed on the stack. But what about `fchmodat()` or `sigaction()`. Yeah, you need to get back to man page. How cool would be to open a binary and get this:
![after]({{site.url}}/assets/images/after.png){:class="center"}

This is exactly what [Annotator](https://github.com/carstein/Annnotater) plugin does - it iterates through all instruction in the code building a virtual stack as it goes, but instead of variables it tracks instructions that pushed a given variable on to the stack. Upon encountering a call of known function it uses this virtual stack to annotate it with a proper argument prototype.

This is a very first release so it is probably riddled with bugs. Not to mention some features are missing. Right now not all glibc function prototypes are present because I haven't found a good and reliable way to extract them from headers - instead I'm using a combination of grep, regex and cut with some manual cleanup effort. That unfortunately takes time. Same goes for system calls, but I should be able to put all Linux 32bit one today. Ah, and you have to run plugin manually in every function you view - right now there is no way to automatically apply it to all the functions - I'm contemplating to write one method allowing user to apply it to whole underlying call graph, but we will see about that.

Another thing is quite naive virtual stack implementation - for sure it requires more work to track stack growth more accurately and for example track number of arguments for functions with va_arg type of arguments. Right now I'm also scanning blocks of code in linear manner, but for future version I will probably switch to recursive mode with stack isolation for each path (well, right now I haven't encountered situation where functions arguments are done in different code block than the call itself, but better safe than sorry). Last thing to improve is number of virtual stacks - first for x64 platforms and later for ARM architecture.

Please, let me know what do you think about the extension and report all the bugs.
