---
layout: post
title: "Code navigation with hx"
date: 2023-06-97
tags:
- Tooling
---
I've been using vim since I've started working with Linux. Admittedly, those times were bit easier - it was either that or Emacs. And I didn't like to press four different keys just to save a file. There was also pico and nano but let's be serious.

I was never a pro Vim user - I think I've started using plugins maybe two years ago and I've never managed to successfully configure a code completion feature. Few months ago somebody showed me the vim successor - [helix](https://helix-editor.com/). It quickly became my go-to editor for situations where breaking VS Code looks like an overkill.

I don't write nearly as much code as I read so code navigation is a primary feature that I look for. I was happy to find that helix in this department has a lot to offer.

## Symbols
I typically start the code review by looking at functions and structures if something catches my eye.

To display symbols in a given workspace just press `space` followed by a `s` or `S` - depending if you want to limit yourself to a currently open file or you want to operate in the entire workspace.

## Find definition/declaration
Another action that I perform quite frequently is finding a definition/declaration of the function that I've encountered while reading code.

> A little bit about the semantic used in this article - whenever I tell you to press `xy` it means to press letter `x` followed by the letter `y` - they don't have to be pressed simultaneously, just follow each other. 

To do that get the cursor on a code symbol and press `gd` or `gD` - depending if you want to get declaration or definition. You might want to ask what is the difference - in all the languages except *C/C++* there is none. 

## Show references
Once you have the function reviewed you probably want to check where else it is being used. To find out get the cursor on the function name and press `gr`. 
Get on the function name and press `gr`

## Jump/display structure
Displaying structure works the same way as displaying definition of a function. Move your cursor one the structure name and press `gd`. 

Unfortunately, right now it's not possible to display popup window with the entire type definition alongside the main coding view - unless of course you are prepared to use two different windows at the same time.

## Go back
Now, the main problem with navigation in various editors is not moving forward - it is moving back. I happened to me multiple times that while chasing some parameter I've found myself six levels deep and not sure how exactly to go back. Over the years I have tried multiple different methods and bookmarks plugin in VS Code was on the top of my list. That is until I discovered jumplist. Every time you execute a command that navigates to a different place in the code your latest position gets saved into a jumplist.

You can display jumplist in quite a simple way - just press `space` followed by `j` - that will show you all the jump points. The most recent one is always at the bottom.
You can also add your own jump point by pressing `ctrl+s`. If you want to speed up your workflow you can also press `ctrl+o` to jump back just one step.

## Summary
There was important thing that needs to be said - most of those features depend on the presence of Language Server - run `hx --health` to check if your configuration support given language.

I had no problem navigating code in Rust and Go but C/C++ had me curse *clangd* multiple times - that is until I've discovered the reason. It only works on self-container files. 
Read this [issue](https://github.com/clangd/clangd/issues/45) if you want to understand the problem better and this [article](https://www.frogtoss.com/labs/clangd-with-unity-builds.html) if you are looking for a solution proposal.