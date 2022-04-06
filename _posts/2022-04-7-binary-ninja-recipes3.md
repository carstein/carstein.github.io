# Notes about Binary Ninja workshop

## workshop plan

In general, I would like 3 segments running 20 minutes of theory and 20 minutes left for exercise.

Let's try to use NewsServer as an binary for examples.

### Segment 1 - intro

Introduce people to concept of binary view and architectures as well as functions, blocks, lines and symbols.

Have some sample code, where we can exercise following:

- how many functions there are
- which function has most blocks
- find all symbols
- find all imported functions

### Segment 2 - ILs

Introduce people to various intermediate languages. 
Teach people how to parse them. If we have time - value analysis. Extract params of the functions.

Exercises: hunting for string format vulnerability.

### Segment 3 - SSA

Introduce people to static single assignment - how to slice forward and backward.

Exercise: Find precondition for integer overflow/heap overflow by locating a malloc with 
