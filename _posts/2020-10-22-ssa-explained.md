---
layout: post
title: "SSA Explained"
date: 2020-10-22
---

# SSA Explained

Recent training about program analysis I took made me realize that I had a very early draft of this post for almost a year and I think this moment as good as any to finally publish it.

SSA form in Binary Ninja was introduced almost two years ago but I think many people don't know nearly enough about it. For me this is one of the strongest selling points for the whole platform and to my knowledge neither IDA nor Ghidra offer anything even close to this powerful feature.

The intention of this post is to show you how easily you can take advantage of it and what amazing results you can achieve.

## Theory

Static Single Assignment commonly abbreviated as `SSA` is a representation of a program in which every variable is defined only once. In cases where the program assigns a new value to an existing variable the new *version* of this variable is created instead. Let's look at a simple example. 

```c
a = 1
b = 2
a = a + b
```

Translating this set of equations into a SSA form we would get

```c
a^1 = 1
b^1 = 2
a^2 = a^1 + b^1
```
Because we've tried to reassign value to an `a` variable the SSA form created a version 2 of the said variable.

> In proper notation the variable version is marked in a subscript but I have absolutely no heart to fight with the blog CSS. Hopefully one day I will have enough motivation to amend it.

In cases where program might follow different paths depending of the control flow the SSA introduced a concept of phi node (commonly noted as Φ). A Φ node represents all possible values that given variable could take at a current state of the program.

Most commonly SSA form is used by compilers for optimization purposes.

## Basic concepts

SSA is used by Binary Ninja during many lifting operations but it is also exposed via an API. Normally it is not visible in the UI but you can check 'Enable plugin development debugging mode' option in the preferences. This allows you to switch to SSA Mode for every available Intermediate Language view of the binary.

API exposes SSA operations are only through the `ssa_form` property of the given function or instruction. Switching to appropriate view is fairly simple:

```python
func_ssa = function.[llil, mlil, hlil].ssa_form
```

Such a view gives us indexed access to all the instructions on which we can later operate. In the upcoming examples I will use the `MLIL` form as this will make some of the examples easier.

First we need to focus on the cornerstone of the method - `SSAVariable`. It has two important properties, `var` giving access to variable itself as well as `version` which is self explanatory. One important piece of knowledge about versions - each local variable starts with version 1 but external variables (like function arguments) starts as version 0.

Once we have our `SSAVariable` we can use it as an argument in two important API calls:

- `current_mlil.ssa_form.get_ssa_var_definition(ssa_var)`
- `current_mlil.ssa_form.get_ssa_var_uses(ssa_var)`

First method gives us exactly one instruction where given variable was created - we can think about it as all the instructions where given variable exist on the left side of the assignment operation. Second one gives us all the instructions where given variable is used - per analogy - variable exist on the right side of the assignment.

Equipped with this knowledge let's try to solve some semi-real world problem.

## Usage examples

Let's consider this trivial function where we have two calls to `malloc()` function with various arguments.

```c
void f1(size_t x) {
  size_t a = 100;

  void* ptr1 = NULL;
  void* ptr2 = NULL;

  ptr1 = malloc(a + x);
  ptr2 = malloc(x);

  free(ptr1);
  free(ptr2);
}
```

Now we would like to analyze the program containing it to see if in any case call accept an argument that was a subject of an arithmetic operation. 

Example of a snippet that would solve this problem is presented bellow.

```python
def step_up(var):
  df = func_ssa.get_ssa_var_definition(var) #3
  log_info("-> {}".format(df))
 
  if df: #4
    if df.src.operation == MediumLevelILOperation.MLIL_ADD:
      log_info("+++ Arthmetic operation")

    right_side = df.vars_read # 5
    if right_side:
      step_up(right_side[0])

## Start
malloc_calls = []

func = bv.get_function_at(0x1169)
func_ssa = func.mlil.ssa_form

malloc_calls.append(func.mlil.ssa_form[6])
malloc_calls.append(func.mlil.ssa_form[10])

log_info("----------")
for call in malloc_calls:
  log_info("Processing {}".format(call))
  arg = call.params[0] #1
  log_info("malloc({})".format(arg))
  step_up(arg.src) #2
  
```

Before we start analyzing it I would like to explain some shortcuts I've made. In every program we have small amount of code responsible for solving an actual problem and much more code responsible for engineering tasks. I don't want to overburden you by making it your task to figure out which parts are important, therefore some of the values are hardcoded - namely function address and indexes of instructions containing `malloc()` calls. In full fledged program those fragments would have been replaced by a function scanning symbols and extracting proper cross references.[^1]

In the code fragment marked with `#1` we are accessing a very nice feature of calls in MLIL - call parameters. We know that `malloc()` accepts only one and we are interested in tracing it, therefore in `#2` we are passing it to recursive function called `step_up()` in a form of a `SSAVariable`.

Our function does the most important part in line marked with `#3` - it tries to obtain the place where this variable was initially defined and terminates if no definition can be found. However, if definition exist (`#4` ) we examine if the instruction right side operation is an arithmetic one. 

Later on in line `#5` we extract all variables being read (in opposition to being written to)  by a given instruction and recursively look for where they were defined until we reach variable without prior definition.

## Closing words

I am well aware that example I've showed above is just a toy one and we haven't touched many aspects of SSA like inspecting version and working with Φ nodes but my goal here was different - to get you hooked on the power of SSA. Where you go from here is up to you.

I've learned most about SSA and how to effectively use it from Josh Watson excellent post titled *"Vulnerability Modeling with Binary Ninja"*[^2] as well as remarkable Sophia d'Antoine training *"Program Analysis for Vulnerability Research"*.[^3] I highly encourage you to check both sources on your own.

## References

[^1]: This is a good idea for a separate post about Binary Ninja Recipes
[^2]: [https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/](https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/)
[^3]: [https://downloads.immunityinc.com/infiltrate2020-training/Infiltrate_Program_Analysis_for_Vulnerability_Research_Training_2020.pdf](https://downloads.immunityinc.com/infiltrate2020-training/Infiltrate_Program_Analysis_for_Vulnerability_Research_Training_2020.pdf)
