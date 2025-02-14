#include <dlfcn.h>
#include <asl.h>
#include <unistd.h>
#include <fcntl.h>

#include <pthread.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h> 

int _start(unsigned long long webcore_base, uint64_t stage2_payload, uint64_t stage2_len);
int my_strlen(char *str);
int backup_webcontent(const char* dest_path);

void* f_dlopen(const char* filename, int flag);
int f_open(const char *filepath, int flag);
int f_open3(const char *path, int flags, mode_t mode);
ssize_t f_read(int fd, void *buf, size_t nbytes);
size_t f_confstr(int name, char *buf, size_t len);
void* f_dlsym(void *image, char* symbol);
dispatch_semaphore_t f_dispatch_semaphore_create(intptr_t value);
intptr_t f_dispatch_semaphore_signal(dispatch_semaphore_t dsema);
intptr_t f_dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout);
void f_exit(int a1);
int f_fprintf(FILE *stream, const char *format, ...);
kern_return_t f_mach_make_memory_entry_64(vm_map_t target_task, memory_object_size_t *size, memory_object_offset_t offset, vm_prot_t permission, mach_port_t *object_handle, mem_entry_name_port_t parent_entry);
kern_return_t f_mach_port_deallocate(ipc_space_t task, mach_port_name_t name);
int f_memcmp(const void *s1, const void *s2, size_t n);
void *f_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int f_munmap(void *addr, size_t length);
int f_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void * arg);
int f_pthread_join(pthread_t thread, void **retval);
int f_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int f_pthread_mutex_lock(pthread_mutex_t *mutex);
int f_pthread_mutex_unlock(pthread_mutex_t *mutex);
time_t f_time(time_t *tloc);
int f_usleep(useconds_t usec);
kern_return_t f_vm_allocate(vm_map_t target_task, vm_address_t *address, vm_size_t size, int flags);
kern_return_t f_vm_deallocate(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t f_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask,
    int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy,
    vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
kern_return_t f_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t f_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size,
                                  mach_vm_address_t data, mach_vm_size_t *out_size);
mach_port_t f_mach_task_self(void);
int *f_memset(void *s, int c, size_t len);
void *f_memcpy(void *dest, const void *src, size_t n);
int f_close(int fd);
int f_fstat(int fd, struct stat *statbuf);
void *f_malloc(size_t size);
char *f_malloc_char(size_t size);
void f_free(void *ptr);
void f_free_char(char *ptr);
char* f_strcat(char* dest, char* src);
ssize_t f_write(int fd, const void *buf, size_t count);
off_t f_lseek(int fd, off_t offset, int whence);

int overwrite_file_from_source(const char *targetPath, const char *sourcePath);
bool overwrite_file(int fd, const void *sourceData, size_t sourceDataLength);
void *switcheroo_thread(void *arg);
bool unaligned_copy_switch_race(int file_to_overwrite, off_t file_offset, const void* overwrite_data, size_t overwrite_length, bool unmapAtEnd);