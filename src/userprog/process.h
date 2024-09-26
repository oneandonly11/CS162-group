#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;               /* Page directory. */
  char process_name[16];           /* Name of the main thread */
  struct thread* main_thread;      /* Pointer to main thread */
  struct list children;            /* List of child processes */
  struct child_process* child_ptr; /* Pointer to parent's child process */
  struct file* exec_file;          /* executable file resource */
  struct list fds;                 /* file descriptors list*/
  struct lock fds_lock;            /* access fds lock */
};

struct child_process {
  pid_t pid;                  /* Process ID */
  int exit_status;            /* Exit status */
  bool waited;                /* Has process_wait been called on this process? */
  struct list_elem elem;      /* List element */
  struct semaphore wait_sema; /* Semaphore for waiting */
};

struct file_descriptor {
  int fd;                /* File descriptor */
  struct file* file;     /* File resource */
  struct list_elem elem; /* List element */
  struct lock lock;      /* access lock */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
