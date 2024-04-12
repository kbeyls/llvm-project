LLVM_BOLT_GADGET_SCANNER=$HOME/dev/llvm/build_bolt-gadget-scanner_rel/bin/llvm-bolt-gadget-scanner
ulimit -v 16000000; (for i in /usr/lib64/*; do echo $i; date; $LLVM_BOLT_GADGET_SCANNER --allow-stripped  -no-threads --scanners=pacret --noreturnfuncs="__GI___libc_fatal/1,malloc_printerr/1,__GI___chk_fail/1,_ _GI___assert_fail/1,__stack_chk_fail_local/1,__stack_chk_fail@PLT,abort@PLT,__assert_fail@PLT,_ZSt21__glibcxx_assert_failPKciS0_S0_@PLT,__cxa_throw@PLT,_Unwind_Resume@PLT" $i; date; done) > libc64_pacret_16G.out 2>&1 

