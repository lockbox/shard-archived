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
- [x] nextAddress bug in riscv64
- [x] context var bug in riscv64
- [x] riscv64 bin into git
- [ ] riscv32 from quals into git
- [ ] riscv32 from quals working
- [ ] sparc from finals into git
- [ ] sparc from finals working
- [ ] needle gets own file + action exec from main.zig
- [ ] make lifting area nicer to poc on
    - register only
    - pure function (no dependant state -- just args)
    - atomic
    - return
    - jump
- [ ] improve needle outputs
    - resolve all stack manipulation insns
    - better gadget finding

After:
- [ ] arbitrary manager make result enum (ie. catch errors)
- [ ] SHARD wrap new api command and poll all the .bin for all code
- [ ] formalize shard IL
    - [ ] make gluon bindings of IL
- [ ] start working on semantic program translation
- [ ] query for program semantics
