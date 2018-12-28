set(COMPONENT_SRCS "heap_caps.c"
                   "heap_caps_init.c"
                   "heap_trace.c"
                   "multi_heap.c"
                   "malloc.c")

set(CFLAGS -DMSPACES=1 -DONLY_MSPACES=1 -DUSE_LOCKS=2 -DUSE_SPIN_LOCKS=0 -DHAVE_MMAP=0 -Dmalloc_getpagesize=4096 -DMALLOC_FAILURE_ACTION=)

set(COMPONENT_ADD_INCLUDEDIRS "include")
set(COMPONENT_ADD_LDFRAGMENTS linker.lf)
set(COMPONENT_REQUIRES "")

register_component()

if(CONFIG_HEAP_TRACING)
    set(WRAP_FUNCTIONS
        calloc
        malloc
        free
        realloc
        heap_caps_malloc
        heap_caps_free
        heap_caps_realloc
        heap_caps_malloc_default
        heap_caps_realloc_default)

    foreach(wrap ${WRAP_FUNCTIONS})
        target_link_libraries(${COMPONENT_TARGET} "-Wl,--wrap=${wrap}")
    endforeach()

endif()
