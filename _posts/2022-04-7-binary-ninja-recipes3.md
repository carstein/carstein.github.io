---
layout: post
title: "Binary Ninja Recipes #3"
date: 2022-04-06
---


Few weeks ago a friend of mine invited me to give a small workshop about Binary Ninja - vulnerability modeling to be specific. I was super happy to oblige because occasions like that motivate me to actually work on something. I can probably write a separate article about organizing a workshops but for this one I have something different in mind. 

Often when taking part in some sort of training, especially if the codebase (or API) is not terribly familiar you spent majority of time implementing things that are not related to the topic you are trying to learn about.

When I was doing a training about hypervisors I've spent a chunk of time learning how to set random fields in random registers just to be able to run `VMXON` instruction. Thanks [Intel](https://www.felixcloutier.com/x86/vmxon). In case of my training about Binary Ninja it was torturing API into shape. Of course a good workshop lead will try to minimize that, but sadly there is no way around that. Still, I would like to spare all the future generations from having to rediscover clean water hence it's time for another recipe.

## Problem: finding cross references

When it comes to vulnerability analysis the most common pattern is to locate certain function and extract a parameter we might be interested in. Let's say we want to look for string format vulnerabilities - in this case we are interested in format parameter from `*printf` function family. To make this analysis work we need to find all instructions that call this specific function. Let's try to do this now.

It always starts with the symbol or rather, a `bv.symbol`. A `bv` is of course a [BinaryView](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView) and `symbol` is a dictionary containing all symbols defined in a given binary. Actually this dictionary is marked as deprecated and while it still works there is no guarantee it will continue to do so. The modern replacement, at least in version 3 of the product is the function `bv.get_symbols()`. If you already know what kind of symbol you are looking for you can also call `bv.get_symbols_by_name()`.

First surprise you are about to encounter is that for a single name like `malloc` you are going to get three different symbols - `ExternalSymbol`, `ImportAddressSymbol` and `ImportedFunctionSymbol`.  I'm going to make it easy for you - only the last one is the one you need but what is the meaning of other two. For reasons that lie deep in ELF file specification and linking process the first symbol, the `ExternalSymbol` is the one we can start with. It is located in `.extern` section and will have exactly one reference. This reference will lead you to the second symbol - `ImportAddressSymbol` in the `.got_plt` section. This one will also have exactly one reference and it will take you to the most important one - `ImportedFunctionSymbol` in `.plt` section.

> If you are interested in learning more about linking external functions read Appendix A in this [article](https://ropemporium.com/guide.html).

Finally we can extract the address of the symbol and call `bv.get_code_refs(<address>)`. This will finally give us all the places where our symbol is being used. Doing something useful with that information is fairly easy - we can fetch Medium Level IL instruction at that address. Code for the whole task is presented bellow:

```python
def find_functions(name):
  potential_calls = []

  for symbol in bv.get_symbols_by_name(name):
    if symbol.type == SymbolType.ImportedFunctionSymbol:
      for ref in bv.get_code_refs(symbol.address):
        call_instr = ref.function.get_low_level_il_at(ref.address).medium_level_il
        potential_calls.append(call_instr)
 
  return potential_calls

```

This is a fairly simple recipe for fetching all the `medium_level_il` calls to a specific function but I saw students wasting 50% of their assigned time just on this simple task. I hope that next time they won't have to do that.
