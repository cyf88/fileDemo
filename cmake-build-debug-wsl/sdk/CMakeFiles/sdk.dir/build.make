# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/e/35114/fileDemo

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/e/35114/fileDemo/cmake-build-debug-wsl

# Include any dependencies generated for this target.
include sdk/CMakeFiles/sdk.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include sdk/CMakeFiles/sdk.dir/compiler_depend.make

# Include the progress variables for this target.
include sdk/CMakeFiles/sdk.dir/progress.make

# Include the compile flags for this target's objects.
include sdk/CMakeFiles/sdk.dir/flags.make

sdk/CMakeFiles/sdk.dir/src/core_api.cpp.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/core_api.cpp.o: ../sdk/src/core_api.cpp
sdk/CMakeFiles/sdk.dir/src/core_api.cpp.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object sdk/CMakeFiles/sdk.dir/src/core_api.cpp.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/core_api.cpp.o -MF CMakeFiles/sdk.dir/src/core_api.cpp.o.d -o CMakeFiles/sdk.dir/src/core_api.cpp.o -c /mnt/e/35114/fileDemo/sdk/src/core_api.cpp

sdk/CMakeFiles/sdk.dir/src/core_api.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/core_api.cpp.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/core_api.cpp > CMakeFiles/sdk.dir/src/core_api.cpp.i

sdk/CMakeFiles/sdk.dir/src/core_api.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/core_api.cpp.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/core_api.cpp -o CMakeFiles/sdk.dir/src/core_api.cpp.s

sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.o: ../sdk/src/easylogging++.cc
sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.o -MF CMakeFiles/sdk.dir/src/easylogging++.cc.o.d -o CMakeFiles/sdk.dir/src/easylogging++.cc.o -c /mnt/e/35114/fileDemo/sdk/src/easylogging++.cc

sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/easylogging++.cc.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/easylogging++.cc > CMakeFiles/sdk.dir/src/easylogging++.cc.i

sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/easylogging++.cc.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/easylogging++.cc -o CMakeFiles/sdk.dir/src/easylogging++.cc.s

sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.o: ../sdk/src/globalvar.cpp
sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.o -MF CMakeFiles/sdk.dir/src/globalvar.cpp.o.d -o CMakeFiles/sdk.dir/src/globalvar.cpp.o -c /mnt/e/35114/fileDemo/sdk/src/globalvar.cpp

sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/globalvar.cpp.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/globalvar.cpp > CMakeFiles/sdk.dir/src/globalvar.cpp.i

sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/globalvar.cpp.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/globalvar.cpp -o CMakeFiles/sdk.dir/src/globalvar.cpp.s

sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o: ../sdk/src/tri_gmssl.cpp
sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o -MF CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o.d -o CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o -c /mnt/e/35114/fileDemo/sdk/src/tri_gmssl.cpp

sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/tri_gmssl.cpp.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/tri_gmssl.cpp > CMakeFiles/sdk.dir/src/tri_gmssl.cpp.i

sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/tri_gmssl.cpp.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/tri_gmssl.cpp -o CMakeFiles/sdk.dir/src/tri_gmssl.cpp.s

sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.o: ../sdk/src/tri_nal.cpp
sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.o -MF CMakeFiles/sdk.dir/src/tri_nal.cpp.o.d -o CMakeFiles/sdk.dir/src/tri_nal.cpp.o -c /mnt/e/35114/fileDemo/sdk/src/tri_nal.cpp

sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/tri_nal.cpp.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/tri_nal.cpp > CMakeFiles/sdk.dir/src/tri_nal.cpp.i

sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/tri_nal.cpp.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/tri_nal.cpp -o CMakeFiles/sdk.dir/src/tri_nal.cpp.s

sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o: ../sdk/src/tri_skf_api.cpp
sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o -MF CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o.d -o CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o -c /mnt/e/35114/fileDemo/sdk/src/tri_skf_api.cpp

sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/tri_skf_api.cpp.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/tri_skf_api.cpp > CMakeFiles/sdk.dir/src/tri_skf_api.cpp.i

sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/tri_skf_api.cpp.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/tri_skf_api.cpp -o CMakeFiles/sdk.dir/src/tri_skf_api.cpp.s

sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.o: sdk/CMakeFiles/sdk.dir/flags.make
sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.o: ../sdk/src/tri_util.cpp
sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.o: sdk/CMakeFiles/sdk.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.o"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.o -MF CMakeFiles/sdk.dir/src/tri_util.cpp.o.d -o CMakeFiles/sdk.dir/src/tri_util.cpp.o -c /mnt/e/35114/fileDemo/sdk/src/tri_util.cpp

sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sdk.dir/src/tri_util.cpp.i"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/e/35114/fileDemo/sdk/src/tri_util.cpp > CMakeFiles/sdk.dir/src/tri_util.cpp.i

sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sdk.dir/src/tri_util.cpp.s"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/e/35114/fileDemo/sdk/src/tri_util.cpp -o CMakeFiles/sdk.dir/src/tri_util.cpp.s

# Object files for target sdk
sdk_OBJECTS = \
"CMakeFiles/sdk.dir/src/core_api.cpp.o" \
"CMakeFiles/sdk.dir/src/easylogging++.cc.o" \
"CMakeFiles/sdk.dir/src/globalvar.cpp.o" \
"CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o" \
"CMakeFiles/sdk.dir/src/tri_nal.cpp.o" \
"CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o" \
"CMakeFiles/sdk.dir/src/tri_util.cpp.o"

# External object files for target sdk
sdk_EXTERNAL_OBJECTS =

sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/core_api.cpp.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/easylogging++.cc.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/globalvar.cpp.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/tri_gmssl.cpp.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/tri_nal.cpp.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/tri_skf_api.cpp.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/src/tri_util.cpp.o
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/build.make
sdk/libsdk.so: sdk/CMakeFiles/sdk.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/e/35114/fileDemo/cmake-build-debug-wsl/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Linking CXX shared library libsdk.so"
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sdk.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
sdk/CMakeFiles/sdk.dir/build: sdk/libsdk.so
.PHONY : sdk/CMakeFiles/sdk.dir/build

sdk/CMakeFiles/sdk.dir/clean:
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk && $(CMAKE_COMMAND) -P CMakeFiles/sdk.dir/cmake_clean.cmake
.PHONY : sdk/CMakeFiles/sdk.dir/clean

sdk/CMakeFiles/sdk.dir/depend:
	cd /mnt/e/35114/fileDemo/cmake-build-debug-wsl && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/e/35114/fileDemo /mnt/e/35114/fileDemo/sdk /mnt/e/35114/fileDemo/cmake-build-debug-wsl /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk /mnt/e/35114/fileDemo/cmake-build-debug-wsl/sdk/CMakeFiles/sdk.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : sdk/CMakeFiles/sdk.dir/depend

