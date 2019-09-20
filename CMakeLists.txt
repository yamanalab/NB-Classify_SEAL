cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.3.1 LANGUAGES CXX)

# Executable will be in ./bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(setup setup.cpp)
add_executable(encryptModel encryptModel.cpp tools.cpp)
add_executable(classifySingle classifySingle.cpp tools.cpp)
add_executable(classifySingleOpt classifySingleOpt.cpp tools.cpp)
add_executable(classifyMulti classifyMulti.cpp tools.cpp)

# Link Microsoft SEAL
target_link_libraries(setup SEAL::seal)
target_link_libraries(encryptModel SEAL::seal)
target_link_libraries(classifySingle SEAL::seal)
target_link_libraries(classifySingleOpt SEAL::seal)
target_link_libraries(classifyMulti SEAL::seal)

# Import Microsoft SEAL
find_package(SEAL 3.3.1 EXACT REQUIRED)


