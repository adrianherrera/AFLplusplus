add_executable(optimin optimin.cpp)
foreach(LIB MaLib EvalMaxSAT glucose)
    target_include_directories(optimin PRIVATE
        "${CMAKE_SOURCE_DIR}/EvalMaxSAT/lib/${LIB}/src")
    target_link_libraries(optimin ${LIB})
endforeach(LIB)
