set(EXECUTABLE_OUTPUT_PATH ${TOP_PATH}/target)

include_directories(

)

aux_source_directory(${TOP_PATH}/test SRC_LISTS)


link_directories(${TOP_PATH}/target)


add_executable(cryptotest ${SRC_LISTS})
target_link_libraries(cryptotest cryptoo)