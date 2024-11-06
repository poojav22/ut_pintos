#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

//bS
#include "threads/vaddr.h"          // for is_user_vaddr
#include "devices/shutdown.h"       // for shutdown_power_off
#include "filesys/filesys.h"        // for filesys_open
#include "filesys/file.h"           // for struct file, if needed

static bool is_valid_ptr(const void *ptr) {

    return ptr != NULL && is_user_vaddr(ptr) && 
    pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

bool is_valid_buffer(const void *buffer, unsigned size) {
    for (unsigned offset = 0; offset < size; offset += PGSIZE) {
        if (!is_valid_ptr((const char *)buffer + offset)) {
            sys_exit(-1);  // Exit if any part of the buffer is invalid
        }
    }
    if (!is_valid_ptr((const char *)buffer + size - 1)) {
        sys_exit(-1);
    }
    return true;
}
//eS

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    //bS
    //lock_init(&filesys_lock);  // Initialize lock for file system operations     //eS
}

void sys_halt() {
    shutdown_power_off();
}

void sys_exit(int status) {
    struct thread *curr = thread_current();
    curr->exitStatus = status;  
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}

//bS
bool sys_create(const char *file, unsigned initial_size) {
    if (!is_valid_ptr(file)) {
        sys_exit(-1);  // Exit if file pointer is invalid
    }
    return filesys_create(file, initial_size);
}

int sys_open(char *fname) {
    struct file *fptr;
    struct thread* curr = thread_current();
    //add fptr to fdtable at next fd location
    if (!is_valid_ptr(fname)){
        sys_exit(-1);
    }
    if (fname==NULL){
        return -1;
    }
    for (int i=0; i<NUMFILE; i++){
        if (curr->fdtable[i]==NULL){
            fptr = filesys_open(fname);
            if (fptr==NULL){
                return -1;
                }
            curr->fdtable[i]=fptr;
            return i;
        }
    }
    return -1;
}
/*
Writes size bytes from buffer to the open file fd. 
Returns the number of bytes actually written, which may be less than size if some bytes could not be written. 
*/
int sys_write(int fd, const void *buffer, unsigned size) {
    struct thread* curr = thread_current();
    // Validating buffer
    if (!is_valid_ptr(buffer) || !is_valid_ptr((const char *)buffer + size - 1)) {
        sys_exit(-1);  // Exit if buffer is invalid
    }
    if (fd<=0 || fd>=NUMFILE || curr->fdtable[fd]==NULL){       
        sys_exit(-1); // Exit if invalid fd, 0 is stdin,
    }
    // writing to stdout
    if (fd == 1) {  // fd 1 is stdout
        putbuf(buffer, size);
        return size;  // Return the number of bytes written
    }
    else {
        return file_write(curr->fdtable[fd], buffer, size);
    }
}
//eS


/*
 * Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.
 */
//pid_t exec (const char *cmd_line) {

//}

static void syscall_handler(struct intr_frame *f UNUSED)
{
    //bS Check if f->esp is a valid user pointer
    if (!is_valid_ptr(f->esp)) {
        sys_exit(-1);  // Exit with -1 if the stack pointer is invalid
    }   
    //eS

    int *usp = f->esp;
    int callno = *usp;
    //printf("Function call: %d\n", *usp);
    switch (callno) {
    case SYS_HALT:     /* Halt the operating system. */
        sys_halt();
	break;
    case SYS_EXIT:     /* Terminate this process. */
        if (!is_valid_ptr(usp + 1)) {
        sys_exit(-1);  // Exit if the argument pointer is invalid
        }
        sys_exit(*(usp + 1));
	break;
    case SYS_EXEC:     /* Start another process. */
	break;
    case SYS_WAIT:     /* Wait for a child process to die. */
	break;
    case SYS_CREATE:   /* Create a file. */
        if (!is_valid_ptr(usp + 1) || !is_valid_ptr(usp + 2)) {
                sys_exit(-1);  // Validate pointers
            }
        f->eax = sys_create((const char *)*(usp + 1), *(usp + 2));      
	break;
    case SYS_REMOVE:   /* Delete a file. */
	break;
    case SYS_OPEN:     /* Open a file. */
	    f->eax = sys_open(*(usp+1));
    return;
    case SYS_FILESIZE: /* Obtain a file's size. */
	break;
    case SYS_READ:     /* Read from a file. */
	break;

    case SYS_WRITE:    /* Write to a file. */
    //bS       
        if (!is_valid_ptr(usp + 1) || !is_valid_ptr(usp + 2) || !is_valid_ptr(usp + 3)) {
            sys_exit(-1);  // Exit if any argument pointer is invalid
        }
        int fd = *(usp + 1);
        const void *buffer = (const void *)*(usp + 2);
        unsigned size = *(usp + 3);
        
         f->eax = sys_write(fd, buffer, size); // Call sys_write and store the return value in f->eax
        return;
    //eS
    case SYS_SEEK:     /* Change position in a file. */
	break;
    case SYS_TELL:     /* Report current position in a file. */
	break;
    case SYS_CLOSE:    /* Close a file. */
	break;
    case SYS_MMAP:   /* Map a file into memory. */
	break;
    case SYS_MUNMAP: /* Remove a memory mapping. */
	break;
    case SYS_CHDIR:   /* Change the current directory. */
	break;
    case SYS_MKDIR:   /* Create a directory. */
	break;
    case SYS_READDIR: /* Reads a directory entry. */
	break;
    case SYS_ISDIR:   /* Tests if a fd represents a directory. */
	break;
    case SYS_INUMBER: /* Returns the inode number for a fd. */
	break;
    }

}
