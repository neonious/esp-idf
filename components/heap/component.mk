#
# Component Makefile
#

COMPONENT_OBJS := heap_caps_init.o heap_caps.o multi_heap.o heap_trace.o malloc.o

# Flags for dlmalloc
CFLAGS += -DMSPACES=1 -DONLY_MSPACES=1 -DUSE_LOCKS=1 -DUSE_SPIN_LOCKS=0 -DHAVE_MMAP=0 -Dmalloc_getpagesize=4096 -DMALLOC_FAILURE_ACTION= -DLACKS_TIME_H=1

ifdef CONFIG_HEAP_TRACING

WRAP_FUNCTIONS = calloc malloc free realloc heap_caps_malloc heap_caps_free heap_caps_realloc heap_caps_malloc_default heap_caps_realloc_default
WRAP_ARGUMENT := -Wl,--wrap=

COMPONENT_ADD_LDFLAGS = -l$(COMPONENT_NAME) $(addprefix $(WRAP_ARGUMENT),$(WRAP_FUNCTIONS))

endif

COMPONENT_ADD_LDFRAGMENTS += linker.lf
