# shard-archived

Program analysis library, initially messed around with this idea because
I needed help find concurrency bugs, then turned into something to use for ctf.
The idea works well for generic program analysis tasks, current poc
is simple gadget finding (the default baked in stuff should get you things with
jumps + stack updates) on any target that you can load + dump from ghidra,
(including non-public architectures). There's no architecture specific code in
here iirc unlike basically every other ropgadget tool, so it's worked for some
real fun things just as effectively as the normie ctf targets.

Binary is runnable in the `main.zig`, used with the pinned zig compiler it should
yell at you until you provide the right arguments a la `zig build run -- -h` etc.

This is effectively EoL and I'm working on something much less clunky to use
that still retains all the fun parts of doing program analysis / database
development in a language with Zig's `std.MultiArrayList`, and other general
niceties that make data oriented + concurrent programming *fun*.

Requirements:
- bfd + zstd in system libs
- git
- zig master-ish (verified works with `0.12.0-dev.2540+776cd673f`)

powered by
- zig
- SLEIGH

