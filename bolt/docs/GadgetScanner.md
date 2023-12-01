# Scanning for gadgets using BOLT technology

For the past 25 years, a large numbers of exploits have been built and used in
the wild to undermine computer security. The majority of these exploits abuse
memory vulnerabilities in programs, see evidence from
[Microsoft](https://youtu.be/PjbGojjnBZQ?si=oCHCa0SHgaSNr6Gr&t=836),
[Chromium](https://www.chromium.org/Home/chromium-security/memory-safety/) and
[Android](https://security.googleblog.com/2021/01/data-driven-security-hardening-in.html).

It is not surprising therefore, that a large number of mitigations have been
added to instruction sets and toolchains to make it harder to build an exploit
using a memory vulnerability. Examples are: stack canaries, stack clash,
pac-ret, shadow stacks, arm64e, and many more.

These mitigations guarantee a so-called "security property" on the binaries they
produce. For example, for stack canaries, the security property is roughly that
a canary is located on the stack between the set of saved variables and set of
local variables. For pac-ret, it is roughly that there are no writes to the
register containing the return address after either an Authentication
instruction or a Branch-and-link instruction.

From time to time, however, a bug gets found in the implementation such a
mitigations in toolchains. Also, code that is written in assembler by hand
requires the developer to ensure these security properties by hand.

In short, it is often found that a few places in the binary code are not
protected as expected given the requested mitigations. Attackers can and do make
use of those places (sometimes called gadgets) to circumvent to protection that
the mitigation should give.

One of the reasons that such gadgets, or holes in the mitigation implementation,
exist is that typically the amount of testing and verification for these
security properties is pretty limited.

In comparison, for testing functional correctness, or for testing performance,
toolchain and software in general typically get tested with large test suites
and benchmarks and testing and benchmarking plans. In contrast, this typically
does not get done for testing the security properties of binary code.

The `llvm-bolt-gadget-scanner` aims to help bridge that gap by scanning binaries
for the security properties that each implemented mitigation should provide.

## Building `llvm-bolt-gadget-scanner` from source

1. Check out the source repository, e.g. in a directory called `llvm-bolt-gadget-scanner`
2. Make a build directory next to the source directory; e.g. by doing `mkdir build-bolt-rel`
3. Run cmake in this build directory. For a release-with-asserts build, the following
   should work:
   ```
   $ cd build-bolt-rel
   $ cmake -G Ninja \
      -DLLVM_ENABLE_PROJECTS="bolt;lld;clang" \
      -DLLVM_ENABLE_ASSERTIONS=On \
      -DLLVM_TARGETS_TO_BUILD="X86;AArch64;RISCV" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_OPTIMIZED_TABLEGEN=On \
      -DLLVM_PARALLEL_LINK_JOBS=4 \
      ../llvm-bolt-gadget-scanner/llvm
   ```
4. Now run ninja in the build directory as follows to build the
   `llvm-bolt-gadget-scanner` binary:
   ```
   $ ninja llvm-bolt-gadget-scanner
   ```
5. To run regression tests, you can use `llvm-lit`, but you'll need to build it
   (and several dependencies) first:
   ```
   $ ninja llvm-test-depends clang lld llvm-bolt-heatmap llvm-bat-dump merge-fdata
   $ ./bin/llvm-lit -v ../llvm-bolt-gadget-scanner/bolt/test/gadget-scanner/
   ```

## Security properties for specific mitigations

`llvm-bolt-gadget-scanner` implements a number of binary analyses. Each analysis
focusses on a specific binary property that should be guaranteed by a specific
mitigation. The help text for the tool explains how to use it:

```text
USAGE: llvm-bolt-gadget-scanner [options] <executable>

OPTIONS:

GadgetScanner options:

  --scanners=<value> - which gadget scanners to run, default is all
    =pacret          -   pac-ret
    =stack-clash     -   stack-clash
    =all             -   all
```

### pac-ret

#### Formal security properties

For every return instruction, check that the register used to read the return
address from (this is typically `x30`):
* is either not written to at all in the function, or
* the last write to it was by an authenticating instruction (such as `AUTIASP`).

#### What false positives or false negatives might arise?

* After having called a `noreturn` function, compilers may not generate
  authentication instructions. TODO: analyze whether this is fine.

These false positives can be supressed by letting `llvm-bolt-gadget-scanner`
know which functions should be considered `noreturn`, using the command line
option `--noreturnfuncs`. It accepts a comma separated list of function names,
for example `--noreturnfuncs="doesnotreturn/1,assert"`

#### Further notes

This analysis could quite easily be extended to PAuthABI analysis, verifying the
same properties not just for every `ret` instruction, but also for all indirect
control flow instructions, and data loads from vptrs.

### stack clash

#### Background info

See
[the key principles for code generation to prevent a stack clash attack](https://developers.redhat.com/blog/2020/05/22/stack-clash-mitigation-in-gcc-part-3),
as per the RedHat blog post that introduces the stack clash protection idea:

* No single allocation can be greater than a page. The compiler must translate
  large requests into a series of page- or smaller-sized requests.
* As pages are allocated, emit instructions to probe them. (Let's call these
  explicit probes.)
* A series of sub-page allocations without intervening probes can not allocate
  more than a page in total.



#### What properties does llvm-bolt-gadget-scanner aim to look for?
* Properties
  * Each basic block can only change SP by a constant amount? (for variable
    amounts, the compiler needs to produce max page-sized updates and do an
    access then).
  * Can compute how far from top-of-stack at each end of basic block there is
    guaranteed to be a memory access?
  * Confluence operator: max of distance from top-of-stack that is
    closest-to-top-of-stack accessed?
  * Hard part may be in stack updates done by instructions that add/sub
    register, rather than immediate? Do compilers with stack clash even emit
    such instructions?

* Alternative, see https://blog.llvm.org/posts/2021-01-05-stack-clash-protection/:
  > This tool instruments all stack allocation and memory access of a running
  > binary, logs them and checks that no stack allocation is greater than
  > PAGE_SIZE and that we get an actual probing between two allocations.


#### Informal intent of the mitigation

#### Formal security properties

#### What false positives or false negatives might arise?
