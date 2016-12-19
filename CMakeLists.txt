set( LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  Option
  Support
  )

add_clang_executable(clang-sdict
  ClangStringDict.cpp
  )

target_link_libraries(clang-sdict
  clangTooling
  )

install(TARGETS clang-sdict
  RUNTIME DESTINATION bin)
