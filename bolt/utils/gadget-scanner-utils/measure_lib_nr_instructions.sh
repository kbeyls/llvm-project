(for i in `cat ./usr_lib64_r_executable.txt`; do ./count_instructions.sh $i; done) | tee nr_instructions.txt
