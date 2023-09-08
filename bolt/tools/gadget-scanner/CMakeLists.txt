set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  MC
  Object
  Support
  )

add_bolt_tool(llvm-bolt-gadget-scanner
  gadget-scanner.cpp
  DISABLE_LLVM_LINK_LLVM_DYLIB
  )

target_link_libraries(llvm-bolt-gadget-scanner
  PRIVATE
  #LLVMBOLTProfile
  #LLVMBOLTRewrite
  LLVMBOLTUtils
  )

#add_dependencies(bolt llvm-bolt-gadget-scanner)