# struct.foo

Program analysis library, initially created to help find concurrency bugs,
but the idea works well for generic program analysis tasks, current poc
is simple gadget finding.

Requirements:
- bfd + zstd in system libs
- git
- zig master-ish

powered by
- zig
- SLEIGH
- gluon
- btree.c
- egg
- answer set programming
- graphs

# Tasks:
- [ ] tests for registers.zig
- [ ] tests for targets.zig
- [ ] tests for var_references.zig
- [ ] needle gets own shard action
- [ ] needle into own file
- [ ] first draft of full shard ops
    - [ ] make IL bindings
        - python
        - lua
        - gluon
        - typescript
        - other??
- [ ] able to store semantics
- [ ] able to query for semantics
