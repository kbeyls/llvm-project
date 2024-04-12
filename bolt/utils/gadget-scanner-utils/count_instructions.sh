echo $1
objdump -dw $1 --no-addresses --no-show-raw-insn | grep -P '^\t' | wc -l
