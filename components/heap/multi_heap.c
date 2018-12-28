// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <multi_heap.h>
#include "multi_heap_internal.h"

/* Defines compile-time configuration macros */
#include "multi_heap_config.h"

#include "malloc.h"

#include "esp_log.h"
const char *TAG = "multi_heap";

#ifdef MULTI_HEAP_POISONING
#error heap poisoning not supported
#endif /* MULTI_HEAP_POISONING */

void *multi_heap_malloc(multi_heap_handle_t heap, size_t size)
    __attribute__((alias("multi_heap_malloc_impl")));

void multi_heap_free(multi_heap_handle_t heap, void *p)
    __attribute__((alias("multi_heap_free_impl")));

void *multi_heap_realloc(multi_heap_handle_t heap, void *p, size_t size)
    __attribute__((alias("multi_heap_realloc_impl")));

size_t multi_heap_get_allocated_size(multi_heap_handle_t heap, void *p)
    __attribute__((alias("multi_heap_get_allocated_size_impl")));

multi_heap_handle_t multi_heap_register(void *start, size_t size)
    __attribute__((alias("multi_heap_register_impl")));

void multi_heap_get_info(multi_heap_handle_t heap, multi_heap_info_t *info)
    __attribute__((alias("multi_heap_get_info_impl")));

size_t multi_heap_free_size(multi_heap_handle_t heap)
    __attribute__((alias("multi_heap_free_size_impl")));

size_t multi_heap_minimum_free_size(multi_heap_handle_t heap)
    __attribute__((alias("multi_heap_minimum_free_size_impl")));

//void *multi_heap_get_block_address(multi_heap_block_handle_t block)
//    __attribute__((alias("multi_heap_get_block_address_impl")));

void *multi_heap_get_block_owner(multi_heap_block_handle_t block)
{
    return NULL;
}

size_t multi_heap_get_allocated_size_impl(multi_heap_handle_t heap, void *p)
{
    return mspace_usable_size(p);
}

multi_heap_handle_t multi_heap_register_impl(void *start_ptr, size_t size)
{
    multi_heap_handle_t heap = create_mspace_with_base(start_ptr, size, 1);
    mspace_track_large_chunks(heap, 1);

    return heap;
}

void multi_heap_set_lock(multi_heap_handle_t heap, void *lock)
{
    mspace_set_lock(heap, lock);
}

void *multi_heap_malloc_impl(multi_heap_handle_t heap, size_t size)
{
    if (size == 0 || heap == NULL)
        return NULL;

    return mspace_malloc(heap, size);
}

void multi_heap_free_impl(multi_heap_handle_t heap, void *p)
{
    if (p == NULL)
        return;

    mspace_free(heap, p);
}

void *multi_heap_realloc_impl(multi_heap_handle_t heap, void *p, size_t size)
{
    if (p == NULL)
        return multi_heap_malloc_impl(heap, size);
    if (size == 0)
    {
        multi_heap_free_impl(heap, p);
        return NULL;
    }

    return mspace_realloc(heap, p, size);
}

/*
bool multi_heap_check(multi_heap_handle_t heap, bool print_errors)
{
}
*/

void multi_heap_dump(multi_heap_handle_t heap)
{
    mspace_malloc_stats(heap);
}

size_t multi_heap_free_size_impl(multi_heap_handle_t heap)
{
    struct mallinfo minfo = mspace_mallinfo(heap);
    return minfo.fordblks;
}

size_t multi_heap_minimum_free_size_impl(multi_heap_handle_t heap)
{
    struct mallinfo minfo = mspace_mallinfo(heap);
    return minfo.uordblks + minfo.fordblks - minfo.usmblks;
}

void multi_heap_get_info_impl(multi_heap_handle_t heap, multi_heap_info_t *info)
{
    struct mallinfo minfo = mspace_mallinfo(heap);

    memset(info, 0, sizeof(multi_heap_info_t));
    info->total_allocated_bytes = minfo.uordblks;
    info->total_free_bytes = minfo.fordblks;
    info->largest_free_block = minfo.fordblks;     // well, could be
    info->allocated_blocks = minfo.uordblks;
    info->free_blocks = minfo.fordblks;
    info->total_blocks = minfo.uordblks + minfo.fordblks;
}