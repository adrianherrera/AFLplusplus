add_definitions(${LLVM_DEFINITIONS})

add_executable(optimin optimin.cpp)
foreach(LIB MaLib EvalMaxSAT glucose)
    target_include_directories(optimin PRIVATE
        "${CMAKE_SOURCE_DIR}/EvalMaxSAT/lib/${LIB}/src")
    target_link_libraries(optimin ${LIB})
endforeach(LIB)

llvm_map_components_to_libnames(LLVM_LIBS support)
target_link_libraries(optimin ${LLVM_LIBS})

target_include_directories(optimin PRIVATE ${LLVM_INCLUDE_DIRS})
install(TARGETS optimin RUNTIME DESTINATION bin)
