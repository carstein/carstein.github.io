---
layout: post
title: "System programming in Rust - part 2"
date: 2022-09-11
tags:
- System programming
- Rust
---

# System programming in rust - part 2

## Little intro

Some time ago I promised to write more about System Programming in Rust. The only problem was - I didn't have a good idea what specifically I can write about. Sure, I use Rust now and then but beyond ptrace and shared memory access (need to finish that Fuzzing series) my experiences with system programming were fairly limited. Or at least that was my impression.

The best source about said topic I know is *The Linux Programming Interface* by [https://man7.org/tlpi/](https://man7.org/tlpi/). Skimming the table of contents looking for inspiration I've realized that there are multiple topics that I can write about. The only thing that was stopping me was my perception that those topics aren't interesting enough to warrant your attention. Nevertheless I've decided to give it a try. If this doesn't work I will revert to some other fields.

Of course my intention is not to merely rewrite things into Rust - that would be pointless and probably would infringe the copyright. I will try to provide a Rust perspective and for a more complete picture I encourage you to check said book.

## Working with files

One of the first chapters in the book talks about working with files so this is going to be our main focus.

Let us start with a simple program that opens a file and reads its content into a buffer. In many aspects it is very different from typical *C* code but it is fulfilling the same goal. 

```rust
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn main() {
    let file_path = Path::new("test.txt");

    match File::open(file_path) {
        Ok(mut file) => {
            // Read to a fil
            let file_length = file.metadata().unwrap().len();
            let mut buf = vec![0; file_length as usize];
            file.read(&mut buf).unwrap();
            println!(">> {:?}", buf);
        },
        Err(err) => {
            eprintln!("Failed to open {} -> {}", file_path.display(), err);
        }
    }
}
```

It probably didn't take you long to figure out that the most important function here is `File::open`. You might be tempted to read the entire [documentation](https://doc.rust-lang.org/std/fs/struct.File.html) on your own but let's work with some basic elements first.

### Arguments

 The function in question has a following definition: `fn open<P: AsRef<Path>>(path: P) -> Result<File>`. First element that is different from a pure *C* version is the argument specifying the file path. In *C* we would deal with a null terminated string (well, technically an array of chars) but in Rust we need to provide a `Path`. Why is that? I'm so glad you have asked.

> Again, technically not only `Path` but any object that upon dereferencing will give us `Path`.

First of all, `Path` provides a set of operations for working with, well, paths - it knows how to extract base directory, get a file name etc. This is however merely a convenience - the real reason behind that is that `Path` is essentially a thin wrapper around another type - an `OsString`.

Strings in Rust are always valid *UTF-8* and might contain zeros inside while in various operating systems a file name cannot. Hence the *bridge* type to help us represent a file name and be easily convertible to a string.

### Return value and errors

Next element worth discussing is the return type. In *C* we would be given a *file descriptor* that would also, with the value -1 signal some kind of error while opening a file. Rust fortunately ditches this antiquated and confusing concept and replaces it with *[Result](https://doc.rust-lang.org/std/result/)*. In simple terms - value returned from `File::open` must be unpacked into either a *file handler* or an *error*.

As for the error - it will be expressed by one of the values from ` io::Error`. In the example code we do not differentiate what kind of error has occurred - we simply capture them all and display the translated code back to a user. If however you would like to treat various types of potential errors differently nothing stops you from adding additional *match* arms.

> An interesting fact that I've skipped over to save you time - to print error we are using the `eprintln!` macro. The only difference between it and standard `println!` is that the former one writes to *stderr* instead of *stdout*. After all those are *file descriptors* as well.

Assuming we encountered no errors we end up with a *file handler* - here represented by a `File` structure. It will allows us to execute various operations on file. The only thing that should make you puzzled is why do we have to mark it as mutable and does it in any way translate to file being writable?

The simple explanation is that mutability of the `File` has nothing to do with the writability of the file itself - the way we open it keeps the file only readable. So why do we keep it mutable? We need it for reading - because first of all, the state and synchronization of access is beyond the program control and second, reading changes the state of the `File` structure by changing the *file offset*. 

### Metadata

Once the file is finally open we probably want to know something about it. Like for example who is the owner, what is the file length or some other things. For that we have a `metadata()` call - it returns a `Metadata` structure (again, wrapped in `Result`). Once we have it we can call various other methods - for additional information you might want to check [documentation](https://doc.rust-lang.org/std/fs/struct.Metadata.html).

Standard metadata object is fairly platform agnostic so it only allows you to call methods that would be universally available everywhere (like length or a type of a file). Platform specific functions are in a way *hidden*. To access them you need to enable it by importing `std::os::unix::fs::MetadataExt`. That will allow you to access fields like *uid*, *gid*, *atime* or [others](https://doc.rust-lang.org/std/os/unix/fs/trait.MetadataExt.html).

### Reading from file

For a normal file descriptor there is only one way to read the content of a file - through a `read()` call. By looking at the [function signature](https://doc.rust-lang.org/std/fs/struct.File.html#impl-Read) we see that it takes the destination buffer as a single argument. Allocation of a buffer is a programmer responsibility and calling read with an uninitialized buffer is not safe and might lead to undefined behavior.

When we call the `read()` method we start reading from the *cursor* (also known as *file offset*) until the end of the file. The one exception is if the buffer is now big enough to fit the content of the file - in this case it will only read as many bytes as the buffer size updating the *cursor* accordingly.

There are obviously multiple variants of the `read()` method - `read_to_string()` that transforms content into a string or `bytes()` that will iterate over individual bytes from a given file. Programmers coming from languages like python are probably going to miss methods that allow reading individual lines but this is not available in the unbuffered mode. Don't worry - we will get to that.

### Closing a file

Astute readers might have noticed that we are not closing files in this example. This is actually by design - the file will be closed automatically the moment the `file` variable goes out of scope. When this happens a `Drop` trait for `File` structure is [called](https://github.com/rust-lang/rust/blob/master/library/std/src/sys/solid/fs.rs#L457) and that causes the file to be closed for us. It very much should remind you about *Context Managers* in Python.

There is however little caveat - any errors encountered during closing a file are ignored. In order to handle them manually you need to call `sync_all` and work with the result of this function.

### Creating a file and permissions

We started our journey by opening a single file using the `File::open()` call but you are probably wondering how to conduct more complex operations - like creating a file or opening one in *append-only* mode. Truth is that `File::open()` call (along with `File::create()`) are just aliases and the foundation upon which they rests is an `std::fs::OpenOptions` [builder](https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#).

A typical example would look like this:

```rust
fn main() {
    let file_path = Path::new("test.txt");

    let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(file_path);
}
```

In the example above we are creating a new file that will be writable and readable but we also truncate it's size to zero.

## Buffered access

Sometimes working with standard reads can be extremely inefficient. Let's say we would like to implement a method that will read content of a file one line at a time. A naive implementation would rely on iterating byte by byte, appending the result into a buffer until we read a new line character. That would mean that we are doing a *syscall* for every byte read.

Fortunately there are better ways to do this. We can [wrap](https://doc.rust-lang.org/std/io/struct.BufReader.html) a file handler in `std::io::BufReader`. This will create an underlying in-memory buffer (right now 8192 bytes long) that will get filled by a single `read()` call and will allow  us to operate on it. 

```rust
fn main() {
    let file_path = Path::new("/etc/passwd");

    match File::open(file_path) {
        Ok(file) => {
            let mut reader = BufReader::new(file);

            for _ in 0..5 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                print!("=> {}", line);
            }
        }
        Err(err) => {
            eprintln!("Problem reading from {}: {}", file_path.display(), err);
        }

    }
}
```

In case we go over the buffer the underlying mechanism will make yet another `read()` call to refill the buffer using the current *file offset*. As you can see the most of the benefits from using the buffered reader (or [writer](https://doc.rust-lang.org/std/io/struct.BufWriter.html#)) materialize when you are making multiple small and repeated operations.

## Closing words

That concludes the first part of the series. As always - I'm planning more parts but it is not my intention to go against my readers. If you have enjoyed this part please let me know and I will write some more. For the sake of completeness I should probably write something about directories, extended attributes as well as monitoring files.
