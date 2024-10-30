#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

static void syscall_handler(struct intr_frame *);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
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

/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written. 
*/

void sys_write(int fd, const void *buffer, unsigned size) {

if (fd==1) {
putbuf(buffer, size);
}
}

int sys_open(char *fname) {
struct file *fptr;
int fd = 0;
fptr = filesys_open(fname);
//add fptr to fdtable at next fd location
//
return fd;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    /* Remove these when implementing syscalls */
  //  printf("system call!\n");
    int *usp = f->esp;
    int callno = *usp;
//printf("Function call: %d\n", *usp);
    switch (callno) {
    case SYS_HALT:     /* Halt the operating system. */
	break;
    case SYS_EXIT:     /* Terminate this process. */
	sys_exit(*(usp+1));
	break;
    case SYS_EXEC:     /* Start another process. */
	break;
    case SYS_WAIT:     /* Wait for a child process to die. */
	break;
    case SYS_CREATE:   /* Create a file. */
	break;
    case SYS_REMOVE:   /* Delete a file. */
	break;
    case SYS_OPEN:     /* Open a file. */
	//f->eax = sys_open(*(usp+1));
	break;
    case SYS_FILESIZE: /* Obtain a file's size. */
	break;
    case SYS_READ:     /* Read from a file. */
	break;
    case SYS_WRITE:    /* Write to a file. */
	sys_write(*(usp+1), (char *)*(usp+2), *(usp+3));
	break;
    case SYS_SEEK:     /* Change position in a file. */
	break;
    case SYS_TELL:     /* Report current position in a file. */
	break;
    case SYS_CLOSE:    /* Close a file. */
	break;

    /* Project 3 and optionally project 4. */
    case SYS_MMAP:   /* Map a file into memory. */
	break;
    case SYS_MUNMAP: /* Remove a memory mapping. */
	break;

    /* Project 4 only. */
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

    thread_exit();
}
