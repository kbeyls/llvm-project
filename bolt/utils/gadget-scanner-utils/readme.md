# llvm-bolt-gadget-scanner utility scripts

This directory contains a few scripts to help with using or running `llvm-bolt-gadget-scanner`.

## How to run the scanner across all libraries in a given directory?

This is a step by step guide on how to run the llvm-bolt-gadget-scanner across all binaries in a directory and how to post-process the output produced to more easily interpret results.

### Step 1. run check_lib64_pacret.sh

The script `check_lib64_pacret.sh` invokes `llvm-bolt-gadget-scanner` on all binaries in a given directory.

Before running it, update at least the first line in the script to point to the location where your `llvm-bolt-gadget-scanner` lives.

### Step 2. process raw outputs.

#### Step 2.1. First run script to count number of instructions in all libraries in a directory

Run the script `count_instruction.sh`, to count the number of instructions in each of the libraries that was scanned.
As follows.

```
$ find /usr/lib64/ -type f -executable > usr_lib64_r_executable.txt
$ (for i in `cat ./usr_lib64_r_executable.txt`; do ./count_instructions.sh $i; done) | tee nr_instructions_lib64.txt
```

#### Step 2.2. Secondly, run script to summarize results

```
$ python3 parse_libc64_out.py < libc64_pacret_16G.out | less
```

Which produces output roughly as follows:

```
Found 3939 libs
After discarding directories: 3753 libs left
After discarding no_nr_instructions: 1985 libs left
```

The above section of the output shows how many binaries actually were processed
The next section of the output shows for how many of the libraries the `llvm-bolt-gadget-scanner` tool crashed, with backtraces:

```
Found 13 crashes: /usr/lib64/libdcerpc-binding.so.0.0.1, /usr/lib64/libglusterfs.so.0.0.1, /usr/lib64/libgnutls-dane.so.0.4.1, /usr/lib64/libgnutls.so.30.37.0, /usr/lib64/libgstreamer-1.0.so.0.2208.0, /usr/lib64/libndr-krb5pac.so.0.0.1, /usr/lib64/libndr-nbt.so.0.0.1, /usr/lib64/libndr.so.3.0.1, /usr/lib64/libndr-standard.so.0.0.1, /usr/lib64/libsamba-errors.so.1.0.0, /usr/lib64/libsamba-hostconfig.so.0.0.1, /usr/lib64/libsmbconf.so.0.0.1, /usr/lib64/libwbclient.so.0.16.
1972 without crashes
Found 1 unique backtraces among crashes
Backtrace 0:
llvm-bolt-gadget-scanner: /home/kribey01/dev/llvm/bolt-gadget-scanner/bolt/lib/Target/AArch64/AArch64MCPlusBuilder.cpp:1140: bool (anonymous namespace)::AArch64MCPlusBuilder::analyzeIndirectBranchFragment(const MCInst &, DenseMap<const MCInst *, SmallVector<MCInst *, 4>> &, const MCExpr *&, int64_t &, int64_t &, MCInst *&) const: Assertion `DefJTBaseAdd->getOpcode() == AArch64::ADDXri && "Failed to match jump table base address pattern! (1)"' failed.
 #0  llvm::sys::PrintStackTrace(llvm::raw_ostream&, int) (/home/kribey01/dev/llvm/build_bolt-gadget-scanner_rel/bin/llvm-bolt-gadget-scanner+0x507182c
 #1  llvm::sys::RunSignalHandlers() (/home/kribey01/dev/llvm/build_bolt-gadget-scanner_rel/bin/llvm-bolt-gadget-scanner+0x506f84c
 #2  SignalHandler(int) Signals.cpp:0:
...
```

The next section of the output shows a sorted list of binaries scanned, from most gadgets found to least gadgets found:

```
/usr/lib64/libphobos2-ldc-debug-shared.so.103.1: 12790 pac-ret gadgets. 13050 rets, 705647 instrs, 10222 CFG functions, 6688 non-CFG functions
/usr/lib64/libphobos2-ldc-shared.so.103.1: 5810 pac-ret gadgets. 10177 rets, 418777 instrs, 8738 CFG functions, 1806 non-CFG functions
/usr/lib64/librsvg-2.so.2.48.0: 5797 pac-ret gadgets. 6226 rets, 640418 instrs, 4258 CFG functions, 646 non-CFG functions
/usr/lib64/librpm_sequoia.so.1: 4818 pac-ret gadgets. 5234 rets, 440354 instrs, 3405 CFG functions, 507 non-CFG functions
/usr/lib64/libdruntime-ldc-debug-shared.so.103.1: 4417 pac-ret gadgets. 4462 rets, 185288 instrs, 3563 CFG functions, 2014 non-CFG functions
/usr/lib64/libmozjs-115.so.0.0.0: 3443 pac-ret gadgets. 21214 rets, 2812397 instrs, 16669 CFG functions, 883 non-CFG functions
/usr/lib64/libwebkit2gtk-4.1.so.0.12.4: 3001 pac-ret gadgets. 149266 rets, 15514152 instrs, 154155 CFG functions, 6340 non-CFG functions
/usr/lib64/libwebkit2gtk-4.1.so.0.12.6: 3000 pac-ret gadgets. 149193 rets, 15515725 instrs, 154162 CFG functions, 6343 non-CFG functions
/usr/lib64/libwebkitgtk-6.0.so.4.4.4: 3000 pac-ret gadgets. 146888 rets, 15255062 instrs, 151592 CFG functions, 5172 non-CFG functions
/usr/lib64/libwebkitgtk-6.0.so.4.4.6: 2999 pac-ret gadgets. 146815 rets, 15256657 instrs, 151599 CFG functions, 5175 non-CFG functions
/usr/lib64/librav1e.so.0.6.6: 2401 pac-ret gadgets. 2694 rets, 372055 instrs, 1547 CFG functions, 187 non-CFG functions
/usr/lib64/libdruntime-ldc-shared.so.103.1: 1825 pac-ret gadgets. 2821 rets, 94545 instrs, 2714 CFG functions, 1077 non-CFG functions
```

For binaries where the number of pac-ret gadgets is a high proportion of all returns instructions, it typically indicates that pac-ret hardening is missing almost completely.

In the results above, probably the top entries are because they contain a lot of code written in Rust or D, for which the compilers on Fedora 39 for those languages do not support or do not enable pac-ret hardening.