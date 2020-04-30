#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/*my implementation*/
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "userprog/process.h"
/*implementation end*/kt

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

//function add
void halt (void);
void exit (int status);
int fork(const char *thread_name);
int exec (const char *cmd_line);
int wait (int pid);
bool create(const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);



/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */


// add
struct lock filesys_lock;

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

/* The main system call interface */


/*--------------------My Implementatoin---------------*/
void
check_address(void *addr){
    if(!is_user_vaddr(addr)){ // minimum hallgguim?
        exit(-1);
    }
}


//get the arguments from stack and put it in arg array. 
void get_argument(struct intr_frame *f, uint64_t *arg, int count){
    for(int i=0;i<count;i++){
        if(i==0){
            arg[i] = f->R.rdi;
        }
        else if(i==1){
            arg[i] = f->R.rsi;
        }
        else if(i==2){
            arg[i] = f->R.rdx;
        }
        else if(i==3){
            arg[i] = f->R.r10;
        }
        else if(i==4){
            arg[i] = f->R.r8;
        }
        else if(i==5){
            arg[i] = f->R.r9;
        }
    }
}

/*-------------------Implementation End--------------*/



void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	uintptr_t **rsp = &f->rsp;
    uint64_t syscall_num = (uint64_t)(f->R.rax);
    uint64_t arg[6];

    //check whether the stack pointer is in user stack
    check_address(*rsp);

    //if the arguments are pointer, check whether the addresses are validate

    //find which case the syscall is
    switch(syscall_num)
    {
        case SYS_HALT:
            halt();
            break;

        case SYS_EXIT:
            get_argument(f, &arg[0],1);
            exit(arg[0]);
            break;

        case SYS_FORK:
            get_argument(f, &arg[0],1);
            fork(arg[0]);
            break;

        case SYS_EXEC:
            get_argument(f, &arg[0],1);
            check_address((void *)arg[0]);
            f->R.rax = exec((const char *)(arg[0]));
            break;

        case SYS_WAIT:
            get_argument(f, &arg[0],1);
            f->R.rax = wait(arg[0]);
            break;

        case SYS_CREATE:
            get_argument(f, &arg[0],2);
            f->R.rax = create((const char *)arg[0],(unsigned)arg[1]);
            break;

        case SYS_REMOVE:
            get_argument(f, &arg[0],1);
            f->R.rax = remove((const char*)arg[0]);
            break;

        case SYS_OPEN:
            get_argument(f, &arg[0],1);
            f->R.rax = open((const char *)arg[0]);
            break;

        case SYS_FILESIZE:
            get_argument(f, &arg[0],1);
            f->R.rax = filesize(arg[0]);
            break;

        case SYS_READ:
            get_argument(f, &arg[0],3);
            f->R.rax = read(arg[0],(void *)arg[1],(unsigned)arg[2]);
            break;

        case SYS_WRITE:
            get_argument(f, &arg[0],3);
            f->R.rax = write(arg[0],(const void *)arg[1],(unsigned)arg[2]);
            break;

        case SYS_SEEK:
            get_argument(f, &arg[0],2);
            seek(arg[0],(unsigned)arg[1]);
            break;

        case SYS_TELL:
            get_argument(f, &arg[0],1);
            f->R.rax = tell(arg[0]);
            break;

        case SYS_CLOSE:
            get_argument(f, &arg[0],1);
            close(arg[0]);
            break;
        
        default:
            break;
            //what to do??
    }
	printf ("system call!\n");
	thread_exit ();
}

//terminates pintos by calling power off
void halt (void){
    power_off();
}

//terminates the current user program, returning status to the kernel.
void exit (int status){
    struct thread *t = thread_current();
    t->exit_status = status;
    printf("%s: exit(%d)\n", t->name, status);
    thread_exit();
}

int fork(const char *thread_name){
    struct thread *cur = thread_current();
    struct thread *child_th;
    tid_t ch_tid;
    
    
    return child_pid;
}

int exec (const char *cmd_line){
    tid_t ch_tid;
    struct thread *child_th;
    ch_tid = process_create_initd(cmd_line);

    child_th = get_child_process(ch_tid);
    if(!child_th == NULL){
        return TID_ERROR;
    }

    if(child_th->load_status == LOAD_BEFORE){
        sema_down(&child_th->sema_load);
    }

    if(child_th->load_status==LOAD_FAIL){
        remove_child_process(child_th);
        return TID_ERROR;
    }
    return ch_tid;
}

int wait (int pid){
    return process_wait(pid);
}


bool create(const char *file, unsigned initial_size){
    bool success;
    lock_acquire(&filesys_lock);
    success = filesys_create(file, initial_size); //lock needed?
    lock_release(&filesys_lock);
    return success;
}


bool remove (const char *file){
    bool success;
    lock_acquire(&filesys_lock);
    success = filesys_remove(file); //lock needed?
    lock_release(&filesys_lock);
    return success;
}

int open (const char *file){
    int fd;
    lock_acquire(&filesys_lock);
    struct file *f_open = filesys_open(file);
    if(f_open == NULL){
        return -1;
    }
    fd = process_add_file(f_open);
    ASSERT(fd !=0);
    ASSERT(fd !=1);

    lock_release(&filesys_lock);
    return fd;
}

int filesize(int fd){
    struct file *f_open = process_get_file(fd);
    if(f_open ==NULL){
        return -1;
    }
    return file_length(f_open);
}

int read(int fd, void *buffer, unsigned size){
    int read_len;
    lock_acquire(&filesys_lock);
    struct file *f_open = process_get_file(fd);
    if(fd==0){
        uint8_t *cur_buf = (uint8_t *)buffer;
        for(unsigned i=0;i<size;i++){
            cur_buf[i] = input_getc(); //right?
        }
        lock_release(&filesys_lock);
        return size;
    }
    else{
        if(f_open == NULL){
            lock_release(&filesys_lock);
            return -1;
        }
        read_len = file_read(f_open,buffer,size);
        lock_release(&filesys_lock);
        return read_len;
    }
}

int write (int fd, const void *buffer, unsigned size){
    int write_len;
    lock_acquire(&filesys_lock);
    struct file *f_open = process_get_file(fd);
    if(fd==1){
        putbuf(buffer,size);
        lock_release(&filesys_lock);
        return size;
    }
    else{
        if(f_open == NULL){
            lock_release(&filesys_lock);
            return 0;
        }
        write_len = file_write(f_open,buffer,size);
        lock_release(&filesys_lock);
        return write_len;
    }
}

void seek (int fd, unsigned position){
    lock_acquire(&filesys_lock);
    struct file *f_open = process_get_file(fd);
    if(f_open == NULL){
        lock_release(&filesys_lock);
        return;
    }
    file_seek(f_open, position);
    lock_release(&filesys_lock);
}

unsigned tell (int fd){
    lock_acquire(&filesys_lock);
    struct file *f_open = process_get_file(fd);
    if(f_open == NULL){
        lock_release(&filesys_lock);
        return -1; // right?
    }
    unsigned result = file_tell(f_open);
    lock_release(&filesys_lock);
    return result;
}

void close(int fd){
    lock_acquire(&filesys_lock);
    process_close_file(fd);
    lock_release(&filesys_lock);
}
