---
layout: post
title: "Translating structures between C and Rust"
date: 2025-03-11
category: "Rust"
tags:
- Rust
---

To do so just add `#[repr(c)]` to the struct declaration. Thank you. Well, we can expand a bit more about that ...

## Background
How did we even end up here and why would we even translate structures between C and Rust? When you do any kind of system programming you will be talking to a kernel. A lot. Sadly you can't do it over Protocol Buffers. Or even Cap'n'Proto. Or, thank god for that, over JSON and XML. You often have to send a pointer to a chunk of memory  through some *syscall* or *ioctl*. Examples? Here you are..
```C
  kvm->mem.slot = 0;
  kvm->mem.guest_phys_addr = 0;
  kvm->mem.memory_size = kvm->ram_size;
  kvm->mem.userspace_addr = kvm->ram_start;

  ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &(kvm->mem));
```

This is the code that initializes the KVM memory region. We just initialize several fields in the `kvm` structure and pass the pointer via the *ioctl* call to the kernel. Simple, right? We should be able to just create a structure in Rust, call the same *ioctl* and be done with it. Sadly, this won't work. To understand why, let's inspect how the structures look in memory. 

## Memory inspector
First of all, we are going to need a simple program that we can use an example.
```c
#include <stdint.h>

struct x {
  uint16_t field_1;
  uint32_t field_2;
  uint16_t field_3;
};

int main(int argc, char *argv[]) {
  struct x variant;
  variant.field_1 = 0x4141;
  variant.field_2 = 0x42424242;
  variant.field_3 = 0x4343;


  return 0;
}
```

Let's cover what is going on - mostly for posterity. Our structure have three fields that have, respectively 16, 32 and again 16 bits. We fill those fields with unique values so it is easy to distinguish them while looking at memory dump.

Checking them under gdb yields following result:
```
pwndbg> x/4x &variant
0x7fffffffdb74: 0x00004141      0x42424242      0x00004343      0xffffdcb8
```

We can see that while the `field_2` occupies 4 bytes (32 bits) as we have requested there is some nasty looking padding in the form of 0 around the values we clearly wanted to be only 2 bytes wide. The reason for that is that certain C standards (like C99) requires two things - structure fields appear in the same order they were declared and addresses of the fields are aligned to 4 bytes. This is why you see those nasty gaps between them.

Let's see what is the Rust opinion about said standard. As we've done previously - let us write a simple program, but this time in Rust.
```rust
#[derive(Debug)]
struct X {
    field1: u16,
    field2: u32,
    field3: u16,
}

fn main() {
    let variant: X = X {
        field1: 0x4141,
        field2: 0x42424242,
        field3: 0x4343,
    };

    println!("{:?}", variant);
}
```

We don't need to explain too much as the program works exactly the same as the previous one. If we look at it in the debugger the results will be bit different.

> Protip: *break variant_rust::main* will get you to your main function. Obviously replace *variant_rust* with the name of your program

```
pwndbg> x/4x $rsp
0x7fffffffd8e0: 0x42424242      0x43434141      0x555a9b10      0x00005555
```

This definitely doesn't look like the C structure. The positive part is that the structure takes less space in memory because it is packed and some fields were rearranged. Obviously Rust compiler can handle that but trying to pass this structure through the FFI boundary is *no bueno*. And if you do, I guarantee some long hours getting very intimate with the debugger trying to figure out why things have just exploded.

So what is the solution? Fortunately Rust has a [directive](https://doc.rust-lang.org/nomicon/other-reprs.html) just for that - `#[repr(C)]`. This will ensure that the resulting structure will be compatible with the C layout, fields won't be rearranged and the correct padding will be used. Use it like this:
```rust
#[derive(Debug)]
#[repr(C)]
struct X {
    field1: u16,
    field2: u32,
    field3: u16,
}
```

There are of course other fun aspects to handle - data type width (`int` should be `i32` but on some old systems it might as well be `i16`), pointers, enums and other fun elements. Read the documentation please. I will write a bit more about this in the next article. 

Ah, right, because I have not mentioned that in the beginning - I am writing a short series of articles about writing your own Virtual Machine Manager using KVM and I have decided to do it in Rust. Stay tuned. 