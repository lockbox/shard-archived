# Quickstart

### Install Dependencies

```bash
$ zigup master
```

### Build

```bash
$ zig build -Doptimize=ReleaseSafe
```

### Dump data from ghidra

1. open binary in ghidra
2. dump filewith script
3. if required `.sla` is not in source tree, add path to it in cli arguments


### Run

```bash
$ zig build run -Doptimize=ReleaseSafe -- -h
```
