/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#define LIBVMI_EXTRA_GLIB
#include <libvmi/libvmi_extra.h>

#define VMI_FAST_CACHE

void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0)
    {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    }
    else
    {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0, mm_offset = 0, pgd_offset = 0;
    status_t status = VMI_FAILURE;
    vmi_init_data_t *init_data = NULL;
    uint64_t domid = 0;
    addr_t mm = 0, pgd = 0;
    uint8_t init = VMI_INIT_DOMAINNAME, config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    time_t end_loop;
    GSList *va_pages = NULL;
    int retcode = 1;

    struct timespec t1;
    struct timespec t2;
    struct timespec t3;

    if ( argc < 2 ) {
        printf("Usage: %s\n", argv[0]);
        printf("\t -n/--name <domain name>\n");
        printf("\t -d/--domid <domain id>\n");
        printf("\t -j/--json <path to kernel's json profile>\n");
        printf("\t -s/--socket <path to KVMI socket>\n");
        return retcode;
    }

    // left for compatibility
    if ( argc == 2 )
        input = argv[1];

    if ( argc > 2 ) {
        const struct option long_opts[] = {
            {"name", required_argument, NULL, 'n'},
            {"domid", required_argument, NULL, 'd'},
            {"json", required_argument, NULL, 'j'},
            {"socket", optional_argument, NULL, 's'},
            {NULL, 0, NULL, 0}
        };
        const char* opts = "n:d:j:s:";
        int c;
        int long_index = 0;

        while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
            switch (c) {
                case 'n':
                    input = optarg;
                    break;
                case 'd':
                    init = VMI_INIT_DOMAINID;
                    domid = strtoull(optarg, NULL, 0);
                    input = (void*)&domid;
                    break;
                case 'j':
                    config_type = VMI_CONFIG_JSON_PATH;
                    config = (void*)optarg;
                    break;
                case 's':
                    // in case we have multiple '-s' argument, avoid memory leak
                    if (init_data) {
                        free(init_data->entry[0].data);
                    } else {
                        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
                    }
                    init_data->count = 1;
                    init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
                    init_data->entry[0].data = strdup(optarg);
                    break;
                default:
                    printf("Unknown option\n");
                    if (init_data) {
                        free(init_data->entry[0].data);
                        free(init_data);
                    }
                    return retcode;
            }
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init_complete(&vmi, input, init
#ifdef VMI_FAST_CACHE
			    | VMI_INIT_EVENTS
#endif
			    , init_data, config_type, config, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }
 
    /* init the offset values */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &tasks_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pgd", &pgd_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_mm", &mm_offset) )
            goto error_exit;
    } else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) )
            goto error_exit;
    } else if (VMI_OS_FREEBSD == vmi_get_ostype(vmi)) {
        tasks_offset = 0;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "freebsd_name", &name_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "freebsd_pid", &pid_offset) )
            goto error_exit;
    }

    /* pause the vm for consistent memory access */
    /*if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    } // if
    */

    /* demonstrate name and id accessors */
    char *name2 = vmi_get_name(vmi);
    vmi_mode_t mode;

    if (VMI_FAILURE == vmi_get_access_mode(vmi, NULL, 0, NULL, &mode))
        goto error_exit;

    if ( VMI_FILE != mode ) {
        uint64_t id = vmi_get_vmid(vmi);

        printf("Process listing for VM %s (id=%"PRIu64")\n", name2, id);
    } else {
        printf("Process listing for file %s\n", name2);
    }
    free(name2);

    os_t os = vmi_get_ostype(vmi);

    /* get the head of the list */
    if (VMI_OS_LINUX == os) {
        /* Begin at PID 0, the 'swapper' task. It's not typically shown by OS
         *  utilities, but it is indeed part of the task list and useful to
         *  display as such.
         */
        if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", &list_head) )
            goto error_exit;

        list_head += tasks_offset;
    } else if (VMI_OS_WINDOWS == os) {

        // find PEPROCESS PsInitialSystemProcess
        if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
            printf("Failed to find PsActiveProcessHead\n");
            goto error_exit;
        }
    } else if (VMI_OS_FREEBSD == vmi_get_ostype(vmi)) {
        // find initproc
        if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "allproc", &list_head) )
            goto error_exit;
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry)) {
        printf("Failed to read next pointer at %"PRIx64"\n", cur_list_entry);
        goto error_exit;
    }

    if (VMI_OS_FREEBSD == vmi_get_ostype(vmi)) {
        // FreeBSD's p_list is not circularly linked
        list_head = 0;
        // Advance the pointer once
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &cur_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer at %"PRIx64"\n", cur_list_entry);
            goto error_exit;
        }
    }

    /* walk the task list */
walk:
    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
    while (1) {

        current_process = cur_list_entry - tasks_offset;

        /* Note: the task_struct that we are looking at has a lot of
         * information.  However, the process name and id are burried
         * nice and deep.  Instead of doing something sane like mapping
         * this data to a task_struct, I'm just jumping to the location
         * with the info that I want.  This helps to make the example
         * code cleaner, if not more fragile.  In a real app, you'd
         * want to do this a little more robust :-)  See
         * include/linux/sched.h for mode details */

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
         * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname) {
            printf("Failed to find procname\n");
            goto error_exit;
        }

        /* print out the process name */
        //printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        if (procname) {
            free(procname);
            procname = NULL;
        }
        
	if (vmi_read_addr_va(vmi, current_process + mm_offset, 0, &mm) != VMI_SUCCESS)
        {
            printf("Failed to read mm at %"PRIx64"\n", current_process + mm_offset);
            goto error_exit;
        }

	if (mm != 0)
        {
            if (vmi_read_addr_va(vmi, mm + pgd_offset, 0, &pgd) != VMI_SUCCESS
                || vmi_translate_kv2p(vmi, pgd, &pgd) != VMI_SUCCESS)
            {
                printf("Failed to read pgd at %"PRIx64"\n", mm + pgd_offset);
                goto error_exit;
            }

	    va_pages = vmi_get_va_pages(vmi, pgd); 
	    GSList *loop = va_pages;
	    addr_t addr = 0;
	    while (loop) {
                page_info_t *page = loop->data;
                addr = page->vaddr;
		loop = loop->next;
	    }
	    
	    uint8_t val;
	    vmi_read_8_va(vmi, addr, pid, &val);

	    GSList *free_this = va_pages;
            while (va_pages) {
                g_free(va_pages->data);
                va_pages=va_pages->next;
            }
            g_slist_free(free_this);
            va_pages = NULL;
        }

        if (VMI_OS_FREEBSD == os && next_list_entry == list_head) {
            break;
        }

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            goto error_exit;
        }
        /* In Windows, the next pointer points to the head of list, this pointer is actually the
         * address of PsActiveProcessHead symbol, not the address of an ActiveProcessLink in
         * EPROCESS struct.
         * It means in Windows, we should stop the loop at the last element in the list, while
         * in Linux, we should stop the loop when coming back to the first element of the loop
         */
        if (VMI_OS_WINDOWS == os && next_list_entry == list_head) {
            break;
        } else if (VMI_OS_LINUX == os && cur_list_entry == list_head) {
	    break;
        }
    };
    clock_gettime(CLOCK_MONOTONIC_RAW, &t2);
    timespec_diff(&t1, &t2, &t3);
    //fprintf(stdout, "%lu\n", t3.tv_nsec);
    //retcode = 0;
    //goto error_exit;

    end_loop = time(NULL) + 2;
    do
    {
#ifdef VMI_FAST_CACHE
        vmi_events_listen(vmi, 100);
#else
	usleep(100000);
#endif
    } while (time(NULL) < end_loop);

    goto walk;

    retcode = 0;
error_exit:
    /* resume the vm */
    //vmi_resume_vm(vmi);

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}
