# VLD Test Projects
cmake_minimum_required(VERSION 3.16)

# Common include directories for all tests
set(VLD_TEST_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/lib/gtest/googletest/include
)

# Common function to set up VLD test targets
function(add_vld_test TARGET_NAME)
    cmake_parse_arguments(ARG "IS_DLL;USE_MFC;HAS_PCH;NO_UNICODE;NO_TEST;USE_STATIC_CRT;NO_VLD_LINK" "PCH_HEADER" "SOURCES;HEADERS;DEPENDS;DEFINITIONS" ${ARGN})
    
    if(ARG_IS_DLL)
        add_library(${TARGET_NAME} SHARED ${ARG_SOURCES} ${ARG_HEADERS})
    else()
        add_executable(${TARGET_NAME} ${ARG_SOURCES} ${ARG_HEADERS})
    endif()
    
    target_include_directories(${TARGET_NAME} PRIVATE ${VLD_TEST_INCLUDE_DIRS})
    
    # Link to vld (unless NO_VLD_LINK is specified)
    if(NOT ARG_NO_VLD_LINK)
        target_link_libraries(${TARGET_NAME} PRIVATE vld)
    endif()
    
    # Additional dependencies
    if(ARG_DEPENDS)
        target_link_libraries(${TARGET_NAME} PRIVATE ${ARG_DEPENDS})
    endif()
    
    # Definitions
    target_compile_definitions(${TARGET_NAME} PRIVATE
        _VARIADIC_MAX=10
        $<$<CONFIG:Debug>:_DEBUG>
        $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
        $<$<NOT:$<CONFIG:Debug>>:VLD_FORCE_ENABLE>
    )
    
    # Unicode support (most tests need it)
    if(NOT ARG_NO_UNICODE)
        target_compile_definitions(${TARGET_NAME} PRIVATE UNICODE _UNICODE)
    endif()
    
    if(ARG_DEFINITIONS)
        target_compile_definitions(${TARGET_NAME} PRIVATE ${ARG_DEFINITIONS})
    endif()
    
    target_compile_definitions(${TARGET_NAME} PRIVATE ${VLD_PLATFORM_DEFINE})
    
    # MFC support
    if(ARG_USE_MFC AND VLD_USE_MFC)
        set_target_properties(${TARGET_NAME} PROPERTIES
            MFC_FLAG 2  # Use MFC as a shared DLL
        )
        target_compile_definitions(${TARGET_NAME} PRIVATE _AFXDLL)
    endif()
    
    # MSVC settings - DLL runtime is set as default in root CMakeLists.txt
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /W3)
        
        # Override to static CRT if requested (needed for some DLLs like vld_dll1/vld_dll2)
        if(ARG_USE_STATIC_CRT)
            set_property(TARGET ${TARGET_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
        
        if(ARG_IS_DLL)
            target_link_options(${TARGET_NAME} PRIVATE /SUBSYSTEM:WINDOWS)
        else()
            target_link_options(${TARGET_NAME} PRIVATE /SUBSYSTEM:CONSOLE)
        endif()
    endif()
    
    # Precompiled headers
    if(ARG_HAS_PCH AND ARG_PCH_HEADER)
        target_precompile_headers(${TARGET_NAME} PRIVATE ${ARG_PCH_HEADER})
    endif()
    
    # Add to tests folder in IDE
    set_target_properties(${TARGET_NAME} PROPERTIES FOLDER "Tests")
    
    # Register with CTest if it's an executable (not a DLL) and not a helper program
    if(NOT ARG_IS_DLL AND NOT ARG_NO_TEST)
        add_test(
            NAME ${TARGET_NAME}
            COMMAND ${TARGET_NAME}
            WORKING_DIRECTORY $<TARGET_FILE_DIR:${TARGET_NAME}>
        )
    endif()
endfunction()

# ============================================================================
# test_basics - Basic VLD tests
# ============================================================================
add_vld_test(test_basics
    SOURCES
        basics/Allocs.cpp
        basics/basics.cpp
        basics/basics_disabled.cpp
        basics/stdafx.cpp
    HEADERS
        basics/Allocs.h
        basics/stdafx.h
        basics/targetver.h
    DEPENDS gtest
    HAS_PCH
    PCH_HEADER basics/stdafx.h
)

# ============================================================================
# testsuite - Main test suite (ANSI build - CharacterSet=NotSet in original)
# ============================================================================
add_vld_test(testsuite
    NO_UNICODE
    SOURCES
        suite/testsuite.cpp
    DEPENDS gtest
)

# ============================================================================
# dynamic - Dynamic library for testing (does NOT link VLD - test uses VLDEnableModule)
# ============================================================================
add_vld_test(dynamic
    IS_DLL
    NO_VLD_LINK
    SOURCES
        dynamic_dll/dynamic.cpp
        dynamic_dll/stdafx.cpp
        basics/Allocs.cpp
    HEADERS
        dynamic_dll/dynamic.h
        dynamic_dll/stdafx.h
        dynamic_dll/targetver.h
        basics/Allocs.h
    DEPENDS gtest
    DEFINITIONS DYNAMIC_EXPORTS
    HAS_PCH
    PCH_HEADER dynamic_dll/stdafx.h
)

# ============================================================================
# dynamic_app - Application that uses dynamic DLL
# ============================================================================
add_vld_test(dynamic_app
    SOURCES
        dynamic_app/dynamic_app.cpp
        dynamic_app/LoadTests.cpp
        dynamic_app/ThreadTest.cpp
        dynamic_app/stdafx.cpp
    HEADERS
        dynamic_app/stdafx.h
        dynamic_app/targetver.h
    DEPENDS dynamic gtest
    HAS_PCH
    PCH_HEADER dynamic_app/stdafx.h
)

# Add dependency on test_mfc if MFC is enabled (runtime LoadLibrary dependency)
if(VLD_USE_MFC AND TARGET test_mfc)
    add_dependencies(dynamic_app test_mfc)
    target_compile_definitions(dynamic_app PRIVATE VLD_MFC_TESTS)
endif()

# ============================================================================
# corruption - Memory corruption tests
# ============================================================================
add_vld_test(corruption
    SOURCES
        corruption/corruption.cpp
        corruption/Tests.cpp
        corruption/stdafx.cpp
    HEADERS
        corruption/stdafx.h
        corruption/targetver.h
    DEPENDS gtest
    HAS_PCH
    PCH_HEADER corruption/stdafx.h
)

# ============================================================================
# vld_main - Helper program spawned by vld_main_test (not a test itself)
# ============================================================================
add_vld_test(vld_main
    SOURCES
        vld_main/vld_main.cpp
        vld_main/stdafx.cpp
    HEADERS
        vld_main/stdafx.h
        vld_main/targetver.h
    HAS_PCH
    PCH_HEADER vld_main/stdafx.h
    NO_TEST  # This is a helper program, not a standalone test
)

# ============================================================================
# tls_init_test - Multi-threaded TLS initialization stress test
# ============================================================================
add_vld_test(tls_init_test
    SOURCES
        tls_init_test/tls_init_test.cpp
)

# ============================================================================
# vld_main_test - Main VLD test with gtest
# ============================================================================
add_vld_test(vld_main_test
    SOURCES
        vld_main_test/vld_main_test.cpp
        vld_main_test/stdafx.cpp
    HEADERS
        vld_main_test/stdafx.h
        vld_main_test/targetver.h
    DEPENDS gtest
    HAS_PCH
    PCH_HEADER vld_main_test/stdafx.h
)
# vld_main_test spawns vld_main.exe - ensure it's built first
add_dependencies(vld_main_test vld_main)

# ============================================================================
# MFC Tests (only when VLD_USE_MFC is ON)
# ============================================================================
if(VLD_USE_MFC)
    # test_mfc - MFC DLL test
    add_vld_test(test_mfc
        IS_DLL
        USE_MFC
        SOURCES
            mfc_dll/mfc.cpp
            mfc_dll/stdafx.cpp
        HEADERS
            mfc_dll/mfc.h
            mfc_dll/stdafx.h
            mfc_dll/targetver.h
            mfc_dll/resource.h
        HAS_PCH
        PCH_HEADER mfc_dll/stdafx.h
    )
    
    set_target_properties(test_mfc PROPERTIES
        VS_MFC_FLAG 2
    )
    
    # Module definition file for MFC DLL
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mfc_dll/mfc.def)
        target_sources(test_mfc PRIVATE mfc_dll/mfc.def)
    endif()
    
    # vldmfc - MFC Application test
    add_executable(vldmfc WIN32
        mfc/vldmfc.cpp
        mfc/vldmfcdlg.cpp
        mfc/StdAfx.cpp
        mfc/vldmfc.rc
        mfc/vldmfc.h
        mfc/vldmfcdlg.h
        mfc/resource.h
        mfc/StdAfx.h
    )
    
    target_include_directories(vldmfc PRIVATE ${VLD_TEST_INCLUDE_DIRS})
    target_link_libraries(vldmfc PRIVATE vld)
    
    target_compile_definitions(vldmfc PRIVATE
        VLD_FORCE_ENABLE
        _WINDOWS
        _AFXDLL
        UNICODE
        _UNICODE
        $<$<CONFIG:Debug>:_DEBUG>
        $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
    )
    
    target_compile_definitions(vldmfc PRIVATE ${VLD_PLATFORM_DEFINE})
    
    # MFC settings - UseOfMfc=Dynamic corresponds to CMAKE_MFC_FLAG=2
    set_target_properties(vldmfc PROPERTIES
        FOLDER "Tests"
        VS_GLOBAL_KEYWORD "MFCProj"
    )
    # CMake's MFC support requires setting this variable before add_executable
    # But since we already added it, we need a workaround using VS generator expression
    set_property(TARGET vldmfc PROPERTY VS_GLOBAL_UseOfMfc "Dynamic")
    
    # MFC requires DLL runtime
    set_property(TARGET vldmfc PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    
    target_compile_options(vldmfc PRIVATE /W3)
    
    # MFC uses its own entry point - just set subsystem
    target_link_options(vldmfc PRIVATE /SUBSYSTEM:WINDOWS)
    
    target_precompile_headers(vldmfc PRIVATE mfc/StdAfx.h)
endif()

# ============================================================================
# Console test (optional, simpler test)
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/console/main.cpp)
    add_vld_test(vldconsole
        SOURCES
            console/main.cpp
    )
endif()

# ============================================================================
# Static string test
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/static_string_test/static_string_test.cpp)
    file(GLOB STATIC_STRING_TEST_SOURCES static_string_test/*.cpp)
    file(GLOB STATIC_STRING_TEST_HEADERS static_string_test/*.h)
    add_vld_test(static_string_test
        SOURCES ${STATIC_STRING_TEST_SOURCES}
        HEADERS ${STATIC_STRING_TEST_HEADERS}
        DEPENDS gtest
    )
endif()

# ============================================================================
# Ignore functions test
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/ignore_functions_test/ignore_functions_test.cpp)
    file(GLOB IGNORE_FUNCTIONS_TEST_SOURCES ignore_functions_test/*.cpp)
    file(GLOB IGNORE_FUNCTIONS_TEST_HEADERS ignore_functions_test/*.h)
    add_vld_test(ignore_functions_test
        SOURCES ${IGNORE_FUNCTIONS_TEST_SOURCES}
        HEADERS ${IGNORE_FUNCTIONS_TEST_HEADERS}
        DEPENDS gtest
    )
    
    # This test needs its own output subdirectory to avoid vld.ini conflicts with other tests
    set_target_properties(ignore_functions_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/ignore_functions_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/ignore_functions_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/ignore_functions_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/ignore_functions_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/ignore_functions_test"
    )
    
    # This test requires its own vld.ini with IgnoreFunctionsList
    # Determine dbghelp architecture for copying
    if(VLD_PLATFORM STREQUAL "ARM64")
        set(DBGHELP_ARCH "arm64")
    elseif(VLD_PLATFORM STREQUAL "x64")
        set(DBGHELP_ARCH "x64")
    else()
        set(DBGHELP_ARCH "x86")
    endif()
    
    add_custom_command(TARGET ignore_functions_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/ignore_functions_test/vld.ini"
            "$<TARGET_FILE_DIR:ignore_functions_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:ignore_functions_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:ignore_functions_test>/dbghelp.dll"
        COMMENT "Copying ignore_functions_test vld.ini, VLD DLL, and dbghelp.dll"
    )
endif()

# ============================================================================
# Destructor-time suppression regression test
#
# Verifies that VLD's automatic destructor report correctly suppresses
# allocations matched by IgnoreFunctionsList / SkipCrtStartupLeaks even when
# user code never called VLDGetLeaksCount or any other VLD API to pre-warm
# the suppression cache. The destructor itself must trigger the cache fill
# before any teardown scope that disables name-based dbghelp resolution
# (relevant on ARM64). This test calls no VLD API; success is determined by
# CTest matching "No memory leaks detected" in the test's stdout.
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/dtor_suppression_test/dtor_suppression_test.cpp)
    add_vld_test(dtor_suppression_test
        SOURCES dtor_suppression_test/dtor_suppression_test.cpp
    )

    # Own output subdirectory so the test's vld.ini does not conflict with peers.
    set_target_properties(dtor_suppression_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/dtor_suppression_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/dtor_suppression_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/dtor_suppression_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/dtor_suppression_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/dtor_suppression_test"
    )

    add_custom_command(TARGET dtor_suppression_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/dtor_suppression_test/vld.ini"
            "$<TARGET_FILE_DIR:dtor_suppression_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:dtor_suppression_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:dtor_suppression_test>/dbghelp.dll"
        COMMENT "Copying dtor_suppression_test vld.ini, VLD DLL, and dbghelp.dll"
    )

    # The test exits with code 0 unconditionally; CTest determines pass/fail
    # by inspecting the VLD destructor's stdout output. PASS requires the
    # "No memory leaks detected" line and FAIL on any actual leak report header.
    set_property(TEST dtor_suppression_test PROPERTY
        PASS_REGULAR_EXPRESSION "No memory leaks detected")
    set_property(TEST dtor_suppression_test PROPERTY
        FAIL_REGULAR_EXPRESSION "Visual Leak Detector detected [0-9]+ memory leak")
endif()

# ============================================================================
# ARM64 process-exit teardown hang regression test
# ============================================================================
if(VLD_PLATFORM STREQUAL "ARM64")
    add_vld_test(arm64_teardown_hang_test
        SOURCES arm64_teardown_hang_test/arm64_teardown_hang_test.cpp
    )
    set_property(TEST arm64_teardown_hang_test PROPERTY TIMEOUT 15)
endif()

# ============================================================================
# Dynamically loaded module symbol resolution regression test
#
# Verifies that VLD resolves function names (via dbghelp) for modules loaded
# AFTER VLD startup via LoadLibrary. The LDR LOADED callback registered by
# VLD (VldDllLoadNotification) calls SymLoadModuleExW for the newly loaded
# module via RegisterLoadedModule, so dbghelp can later resolve symbols in
# that module. Without that registration, leak callstacks for dynamically
# loaded DLLs would degrade to address-only frames.
# The test loads dynamic.dll, calls SimpleLeak_Malloc (which deliberately
# leaks 6 allocations from named functions in dynamic.dll), then exits.
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/dyn_symbol_test/dyn_symbol_test.cpp)
    add_vld_test(dyn_symbol_test
        SOURCES dyn_symbol_test/dyn_symbol_test.cpp
    )
    add_dependencies(dyn_symbol_test dynamic)

    set_target_properties(dyn_symbol_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/dyn_symbol_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/dyn_symbol_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/dyn_symbol_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/dyn_symbol_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/dyn_symbol_test"
    )

    add_custom_command(TARGET dyn_symbol_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/dyn_symbol_test/vld.ini"
            "$<TARGET_FILE_DIR:dyn_symbol_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:dyn_symbol_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:dyn_symbol_test>/dbghelp.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:dynamic>"
            "$<TARGET_FILE_DIR:dyn_symbol_test>/$<TARGET_FILE_NAME:dynamic>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_PDB_FILE:dynamic>"
            "$<TARGET_FILE_DIR:dyn_symbol_test>/dynamic.pdb"
        COMMENT "Copying dyn_symbol_test vld.ini, VLD DLL, dbghelp.dll, dynamic.dll, dynamic.pdb"
    )

    set_property(TEST dyn_symbol_test PROPERTY
        PASS_REGULAR_EXPRESSION "dynamic\\.dll!LeakMemoryMalloc")
    set_property(TEST dyn_symbol_test PROPERTY
        FAIL_REGULAR_EXPRESSION "dynamic\\.dll!0x[0-9A-Fa-f]+\\(")
endif()

# ============================================================================
# No protect-to-read regression test
#
# Loads VLD dynamically with its VirtualProtect import redirected to a counter
# and fails if VLD changes page protection only to read memory. Doing so on
# ntdll data pages crashes x64 processes under x64 emulation on ARM64.
# ============================================================================
add_vld_test(no_protect_to_read_test
    NO_VLD_LINK
    SOURCES no_protect_to_read_test/no_protect_to_read_test.cpp
    DEFINITIONS "VLD_DLL_NAME=L\"$<TARGET_FILE_NAME:vld>\""
)
add_dependencies(no_protect_to_read_test vld)

set_target_properties(no_protect_to_read_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/no_protect_to_read_test"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/no_protect_to_read_test"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/no_protect_to_read_test"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/no_protect_to_read_test"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/no_protect_to_read_test"
)

add_custom_command(TARGET no_protect_to_read_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/no_protect_to_read_test/vld.ini"
        "$<TARGET_FILE_DIR:no_protect_to_read_test>/vld.ini"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:vld>"
        "$<TARGET_FILE_DIR:no_protect_to_read_test>/$<TARGET_FILE_NAME:vld>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
        "$<TARGET_FILE_DIR:no_protect_to_read_test>/dbghelp.dll"
    COMMENT "Copying no_protect_to_read_test vld.ini, VLD DLL, and dbghelp.dll"
)

# ============================================================================
# Deep Callstack Test - Tests for excessively long stack traces (PR #37)
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deep_callstack_test/deep_callstack_test.cpp)
    add_vld_test(deep_callstack_test
        SOURCES
            deep_callstack_test/deep_callstack_test.cpp
    )
endif()

# ============================================================================
# VLD DLLs for unload testing
# ============================================================================
# vld_dll1
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/vld_dll1)
    file(GLOB VLD_DLL1_SOURCES vld_dll1/*.cpp)
    file(GLOB VLD_DLL1_HEADERS vld_dll1/*.h)
    if(VLD_DLL1_SOURCES)
        add_vld_test(vld_dll1
            IS_DLL
            SOURCES ${VLD_DLL1_SOURCES}
            HEADERS ${VLD_DLL1_HEADERS}
        )
    endif()
endif()

# vld_dll2
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/vld_dll2)
    file(GLOB VLD_DLL2_SOURCES vld_dll2/*.cpp)
    file(GLOB VLD_DLL2_HEADERS vld_dll2/*.h)
    if(VLD_DLL2_SOURCES)
        add_vld_test(vld_dll2
            IS_DLL
            SOURCES ${VLD_DLL2_SOURCES}
            HEADERS ${VLD_DLL2_HEADERS}
        )
    endif()
endif()

# vld_unload - Uses LoadLibrary at runtime, no link-time dependency on dll1/dll2
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/vld_unload)
    file(GLOB VLD_UNLOAD_SOURCES vld_unload/*.cpp)
    file(GLOB VLD_UNLOAD_HEADERS vld_unload/*.h)
    if(VLD_UNLOAD_SOURCES)
        add_vld_test(vld_unload
            SOURCES ${VLD_UNLOAD_SOURCES}
            HEADERS ${VLD_UNLOAD_HEADERS}
            DEPENDS gtest
        )
        # Ensure dll1 and dll2 are built before vld_unload (runtime dependency)
        if(TARGET vld_dll1)
            add_dependencies(vld_unload vld_dll1)
        endif()
        if(TARGET vld_dll2)
            add_dependencies(vld_unload vld_dll2)
        endif()
    endif()
endif()

# ============================================================================
# COM Test - MFC/ATL COM DLL with IDL compilation
# ============================================================================
if(VLD_USE_MFC AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/vld_ComTest/ComTest.idl)
    # Find MIDL compiler
    find_program(MIDL_EXECUTABLE midl)
    
    if(MIDL_EXECUTABLE)
        set(COMTEST_IDL ${CMAKE_CURRENT_SOURCE_DIR}/vld_ComTest/ComTest.idl)
        set(COMTEST_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/vld_ComTest)
        
        # Generated files from MIDL
        set(COMTEST_GENERATED_H ${COMTEST_GENERATED_DIR}/ComTest_i.h)
        set(COMTEST_GENERATED_C ${COMTEST_GENERATED_DIR}/ComTest_i.c)
        set(COMTEST_GENERATED_P ${COMTEST_GENERATED_DIR}/ComTest_p.c)
        set(COMTEST_GENERATED_TLB ${COMTEST_GENERATED_DIR}/ComTest.tlb)
        
        # Create output directory
        file(MAKE_DIRECTORY ${COMTEST_GENERATED_DIR})
        
        # Determine target environment for MIDL
        if(VLD_PLATFORM STREQUAL "ARM64")
            set(MIDL_ENV "arm64")
        elseif(VLD_PLATFORM STREQUAL "x64")
            set(MIDL_ENV "x64")
        else()
            set(MIDL_ENV "win32")
        endif()
        
        # Custom command to run MIDL compiler
        add_custom_command(
            OUTPUT ${COMTEST_GENERATED_H} ${COMTEST_GENERATED_C} ${COMTEST_GENERATED_P} ${COMTEST_GENERATED_TLB}
            COMMAND ${MIDL_EXECUTABLE}
                /nologo
                /env ${MIDL_ENV}
                /h ComTest_i.h
                /iid ComTest_i.c
                /proxy ComTest_p.c
                /tlb ComTest.tlb
                /Oicf
                /out ${COMTEST_GENERATED_DIR}
                ${COMTEST_IDL}
            DEPENDS ${COMTEST_IDL}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vld_ComTest
            COMMENT "Compiling IDL file: ComTest.idl"
            VERBATIM
        )
        
        # Custom target for IDL compilation
        add_custom_target(ComTest_idl DEPENDS 
            ${COMTEST_GENERATED_H} 
            ${COMTEST_GENERATED_C}
        )
        
        # C++ source files (use PCH)
        set(COMTEST_CPP_SOURCES
            vld_ComTest/ComTest.cpp
            vld_ComTest/dllmain.cpp
            vld_ComTest/MyMath.cpp
            vld_ComTest/stdafx.cpp
        )
        
        # C source files (no PCH - they're RPC/proxy stubs)
        # Note: xdlldata.c includes dlldata.c conditionally via _MERGE_PROXYSTUB
        # We only need xdlldata.c and the generated ComTest_i.c
        set(COMTEST_C_SOURCES
            vld_ComTest/xdlldata.c
            ${COMTEST_GENERATED_C}
        )
        
        # COM Test DLL
        add_library(ComTest SHARED
            ${COMTEST_CPP_SOURCES}
            ${COMTEST_C_SOURCES}
            vld_ComTest/ComTest.rc
            vld_ComTest/ComTest.def
        )
        
        # Exclude C files from precompiled header
        set_source_files_properties(${COMTEST_C_SOURCES} PROPERTIES
            SKIP_PRECOMPILE_HEADERS ON
        )
        
        # Ensure IDL is compiled before ComTest
        add_dependencies(ComTest ComTest_idl)
        
        target_include_directories(ComTest PRIVATE 
            ${VLD_TEST_INCLUDE_DIRS}
            ${COMTEST_GENERATED_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/vld_ComTest
        )
        
        target_link_libraries(ComTest PRIVATE vld)
        
        # Basic definitions - ATL macros are already in stdafx.h
        target_compile_definitions(ComTest PRIVATE
            _WINDOWS
            _USRDLL
            _AFXDLL
            UNICODE
            _UNICODE
            $<$<CONFIG:Debug>:_DEBUG>
            $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
        )
        
        target_compile_definitions(ComTest PRIVATE ${VLD_PLATFORM_DEFINE})
        
        # MFC settings
        set_target_properties(ComTest PROPERTIES
            FOLDER "Tests"
            VS_GLOBAL_KEYWORD "MFCProj"
        )
        set_property(TARGET ComTest PROPERTY VS_GLOBAL_UseOfMfc "Dynamic")
        
        # MFC requires DLL runtime
        set_property(TARGET ComTest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        
        target_compile_options(ComTest PRIVATE /W3)
        target_link_options(ComTest PRIVATE /SUBSYSTEM:WINDOWS)
        
        # Precompiled header for C++ files only
        target_precompile_headers(ComTest PRIVATE 
            "$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_SOURCE_DIR}/vld_ComTest/stdafx.h>"
        )
        
        message(STATUS "COM Test enabled - MIDL found at: ${MIDL_EXECUTABLE}")
    else()
        message(WARNING "COM Test skipped - MIDL compiler not found")
    endif()
endif()

# ============================================================================
# Ignore modules DLL - Test DLL that intentionally leaks (does NOT link VLD)
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/ignore_modules_dll/ignore_modules_dll.cpp)
    add_vld_test(ignore_modules_dll
        IS_DLL
        NO_VLD_LINK
        NO_UNICODE
        SOURCES
            ignore_modules_dll/ignore_modules_dll.cpp
        HEADERS
            ignore_modules_dll/ignore_modules_dll.h
        DEFINITIONS IGNORE_MODULES_DLL_EXPORTS
    )
endif()

# ============================================================================
# Ignore modules test - Verifies IgnoreModulesList suppresses module leaks
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/ignore_modules_test/ignore_modules_test.cpp)
    add_vld_test(ignore_modules_test
        SOURCES
            ignore_modules_test/ignore_modules_test.cpp
        DEPENDS gtest
    )

    # This test needs its own output subdirectory for its custom vld.ini
    set_target_properties(ignore_modules_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/ignore_modules_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/ignore_modules_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/ignore_modules_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/ignore_modules_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/ignore_modules_test"
    )

    add_custom_command(TARGET ignore_modules_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/ignore_modules_test/vld.ini"
            "$<TARGET_FILE_DIR:ignore_modules_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:ignore_modules_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:ignore_modules_test>/dbghelp.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:ignore_modules_dll>"
            "$<TARGET_FILE_DIR:ignore_modules_test>/$<TARGET_FILE_NAME:ignore_modules_dll>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_PDB_FILE:ignore_modules_dll>"
            "$<TARGET_FILE_DIR:ignore_modules_test>/$<TARGET_PDB_FILE_NAME:ignore_modules_dll>"
        COMMENT "Copying ignore_modules_test vld.ini, VLD DLL, dbghelp.dll, test DLL and PDB"
    )

    add_dependencies(ignore_modules_test ignore_modules_dll)
endif()

# ============================================================================
# Ignore modules getaddrinfo test - Verifies rasadhlp.dll suppression
# ============================================================================
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/ignore_modules_getaddrinfo_test/ignore_modules_getaddrinfo_test.cpp)
    add_vld_test(ignore_modules_getaddrinfo_test
        SOURCES
            ignore_modules_getaddrinfo_test/ignore_modules_getaddrinfo_test.cpp
        DEPENDS gtest
    )

    # This test needs its own output subdirectory for its custom vld.ini
    set_target_properties(ignore_modules_getaddrinfo_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/ignore_modules_getaddrinfo_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/ignore_modules_getaddrinfo_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/ignore_modules_getaddrinfo_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/ignore_modules_getaddrinfo_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/ignore_modules_getaddrinfo_test"
    )

    add_custom_command(TARGET ignore_modules_getaddrinfo_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/ignore_modules_getaddrinfo_test/vld.ini"
            "$<TARGET_FILE_DIR:ignore_modules_getaddrinfo_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:ignore_modules_getaddrinfo_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:ignore_modules_getaddrinfo_test>/dbghelp.dll"
        COMMENT "Copying ignore_modules_getaddrinfo_test vld.ini, VLD DLL, and dbghelp.dll"
    )

    # getaddrinfo_leaks_test - Counterpart to ignore_modules_getaddrinfo_test.
    # Proves that getaddrinfo+freeaddrinfo produces system DLL false-positive
    # leaks WITHOUT IgnoreModulesList. This validates that the suppression in
    # ignore_modules_getaddrinfo_test is actually doing real work.
    add_vld_test(getaddrinfo_leaks_test
        SOURCES
            getaddrinfo_leaks_test/getaddrinfo_leaks_test.cpp
        DEPENDS gtest
    )

    # This test needs its own output subdirectory for its custom vld.ini
    set_target_properties(getaddrinfo_leaks_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/getaddrinfo_leaks_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/getaddrinfo_leaks_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/getaddrinfo_leaks_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/getaddrinfo_leaks_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/getaddrinfo_leaks_test"
    )

    add_custom_command(TARGET getaddrinfo_leaks_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/getaddrinfo_leaks_test/vld.ini"
            "$<TARGET_FILE_DIR:getaddrinfo_leaks_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:getaddrinfo_leaks_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:getaddrinfo_leaks_test>/dbghelp.dll"
        COMMENT "Copying getaddrinfo_leaks_test vld.ini, VLD DLL, and dbghelp.dll"
    )

    # getaddrinfo_missing_free_test - Proves VLD detects when application code
    # calls getaddrinfo without a matching freeaddrinfo. Runs in its own
    # process so DLL loading state is clean (no interference from other tests).
    add_vld_test(getaddrinfo_missing_free_test
        SOURCES
            getaddrinfo_missing_free_test/getaddrinfo_missing_free_test.cpp
        DEPENDS gtest
    )

    set_target_properties(getaddrinfo_missing_free_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/getaddrinfo_missing_free_test"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug/getaddrinfo_missing_free_test"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release/getaddrinfo_missing_free_test"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo/getaddrinfo_missing_free_test"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel/getaddrinfo_missing_free_test"
    )

    add_custom_command(TARGET getaddrinfo_missing_free_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/getaddrinfo_missing_free_test/vld.ini"
            "$<TARGET_FILE_DIR:getaddrinfo_missing_free_test>/vld.ini"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:vld>"
            "$<TARGET_FILE_DIR:getaddrinfo_missing_free_test>/$<TARGET_FILE_NAME:vld>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/setup/dbghelp/${DBGHELP_ARCH}/dbghelp.dll"
            "$<TARGET_FILE_DIR:getaddrinfo_missing_free_test>/dbghelp.dll"
        COMMENT "Copying getaddrinfo_missing_free_test vld.ini, VLD DLL, and dbghelp.dll"
    )
endif()
