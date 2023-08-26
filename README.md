# struct.foo

Program analysis library, initially created to help find concurrency bugs,
but the idea works well for generic program analysis tasks, current poc
is simple gadget finding.

Requirements:
- bfd + zstd in system libs
- git
- zig master-ish (verified works with `0.12.0-dev.170+750998eef`)

powered by
- zig
- SLEIGH
- gluon
- btree.c
- egg
- answer set programming
- graphs

# Tasks:
- [x] tests for registers.zig
- [ ] tests for targets.zig (TBD)
- [x] targets converted to a single struct
- [ ] tests for var_references.zig (TBD)
- [ ] needle gets own shard action
- [ ] needle into own file
- [ ] first draft of full shard ops
- [ ] make shard IL bindings
    - [ ] shard lua
    - [ ] shard typescript
- [ ] able to store semantics
- [ ] able to query for semantics
