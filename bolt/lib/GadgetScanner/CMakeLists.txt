add_llvm_library(LLVMBOLTGadgetScanner
  Utils.cpp

  DISABLE_LLVM_LINK_LLVM_DYLIB

  LINK_LIBS
  ${LLVM_PTHREAD_LIB}

  DEPENDS
  llvm_vcsrevision_h

  LINK_COMPONENTS
  Support
  )
