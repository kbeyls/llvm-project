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
    =all             -   all
```

### pac-ret

TODO

### stack clash

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
