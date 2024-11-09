#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct process_data {
  char* cmd_line;
  struct semaphore load_sema;
  struct child_process* child_ptr;
  bool loaded;
};

struct pthread_data {
  stub_fun sf;
  pthread_fun tf;
  void* arg;
  struct pthread* pthread;
  struct semaphore sema;
  tid_t tid;
  bool success;
};

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
static bool setup_thread(void (**eip)(void), void** esp, stub_fun sf);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;
  t->pcb->main_thread = t;
  list_init(&t->pcb->children);
  t->pcb->child_ptr = NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {

  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  size_t file_name_size = strnlen(file_name, PGSIZE) + 1;
  char* fn_copy = malloc(file_name_size);
  if (fn_copy == NULL) {
    return TID_ERROR;
  }
  strlcpy(fn_copy, file_name, file_name_size);

  struct process_data* pd = malloc(sizeof(struct process_data));
  if (pd == NULL) {
    free(fn_copy);
    return TID_ERROR;
  }
  pd->cmd_line = fn_copy;
  pd->loaded = false;
  sema_init(&pd->load_sema, 0);

  struct child_process* cp = malloc(sizeof(struct child_process));
  if (cp == NULL) {
    free(fn_copy);
    free(pd);
    return TID_ERROR;
  }
  cp->pid = TID_ERROR;
  cp->exit_status = -1;
  cp->waited = false;
  list_init(&cp->elem);
  sema_init(&cp->wait_sema, 0);
  pd->child_ptr = cp;

  size_t thread_name_size = strcspn(fn_copy, " ") + 1;
  char* thread_name = malloc(thread_name_size);
  if (thread_name == NULL) {
    free(fn_copy);
    free(pd);
    free(cp);
    return TID_ERROR;
  }
  strlcpy(thread_name, fn_copy, thread_name_size);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(thread_name, PRI_DEFAULT, start_process, pd);
  if (tid == TID_ERROR) {
    free(fn_copy);
    free(pd);
    free(cp);
    free(thread_name);
    return TID_ERROR;
  }

  sema_down(&pd->load_sema);
  if (!pd->loaded) {
    free(fn_copy);
    free(pd);
    free(cp);
    free(thread_name);
    return TID_ERROR;
  }
  cp->pid = tid;
  list_push_back(&thread_current()->pcb->children, &cp->elem);
  free(thread_name);
  free(pd);
  free(fn_copy);
  return tid;
}

static int get_args_num(char* args_str) {
  if (!args_str) {
    return 0;
  }
  int num = 0;
  bool next_args = true;
  for (size_t i = 0; i < strlen(args_str); i++) {
    if (args_str[i] == ' ') {
      next_args = true;
    } else {
      if (next_args) {
        num++;
        next_args = false;
      }
    }
  }
  return num;
}

void push_arguments(void** esp, char* file_name, char* saved_ptr) {
  uint8_t* stack = *esp;
  /* fill in the args in stack */
  if (saved_ptr) {
    int args_len = strlen(saved_ptr);
    stack -= args_len + 1;
    strlcpy((char*)stack, saved_ptr, args_len + 1);
    saved_ptr = (char*)stack;
  }
  /* fill in filename in stack */
  int file_name_len = strlen(file_name);
  stack -= file_name_len + 1;
  strlcpy((char*)stack, file_name, file_name_len + 1);
  file_name = (char*)stack;
  /* one more for file name */
  int args_num = get_args_num(saved_ptr) + 1;
  /* calculate all bytes to align
     argv[] one more for null-terminated argv
     argc, argv
   */
  int args_bytes_len = (args_num + 1) * 4 + 4 + 4;
  /* stack align */
  stack -= args_bytes_len;
  stack = (uint8_t*)((uint32_t)stack & ~15);
  /* one more for return address*/
  stack -= 4;
  *esp = stack;
  /* fill return and argv[n] */
  memset(stack, 0, args_bytes_len + 4);
  stack += 4;
  /* fill argc argv */
  *((uint32_t*)stack) = (uint32_t)args_num;
  stack += sizeof(int);
  *((uint32_t*)stack) = (uint32_t)(stack + 4);
  stack += sizeof(char**);
  /* fill argv[] */
  *((uint32_t*)stack) = (uint32_t)file_name;
  stack += sizeof(char*);
  if (saved_ptr) {
    for (char* token = strtok_r(NULL, " ", &saved_ptr); token != NULL;
         token = strtok_r(NULL, " ", &saved_ptr)) {
      *((uint32_t*)stack) = (uint32_t)token;
      stack += sizeof(char*);
    }
  }
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* data) {
  struct process_data* pd = data;
  char* save_ptr;
  char* program_name;
  program_name = strtok_r(pd->cmd_line, " ", &save_ptr);
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    list_init(&t->pcb->children);
    list_init(&t->pcb->fds);
    list_init(&t->pcb->pthreads);
    lock_init(&t->pcb->pthreads_lock);
    sema_init(&t->pcb->main_wait, 0);
    lock_init(&t->pcb->fds_lock);
    list_init(&t->pcb->locks);
    list_init(&t->pcb->semas);
    t->pcb->child_ptr = pd->child_ptr;
    t->pcb->exec_file = NULL;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    asm volatile("fninit; fsave (%0)" : : "g"(&if_.fpu));
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(program_name, &if_.eip, &if_.esp);
  }

  if (success) {
    push_arguments(&if_.esp, program_name, save_ptr);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  } else {
    pd->loaded = success;
  }

  sema_up(&pd->load_sema);

  /* Clean up. Exit on failure or jump to userspace */
  if (!success) {

    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

struct child_process* find_child(pid_t child_pid) {
  struct thread* cur = thread_current();
  struct list_elem* e;
  for (e = list_begin(&cur->pcb->children); e != list_end(&cur->pcb->children); e = list_next(e)) {
    struct child_process* cp = list_entry(e, struct child_process, elem);
    if (cp->pid == child_pid) {
      return cp;
    }
  }
  return NULL;
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct thread* cur = thread_current();
  struct child_process* cp = find_child(child_pid);
  if (cp == NULL || cp->waited) {
    return -1;
  }
  cp->waited = true;
  sema_down(&cp->wait_sema);
  int exit_status = cp->exit_status;
  list_remove(&cp->elem);
  free(cp);

  return exit_status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  if (!is_main_thread(cur, cur->pcb)) {
    cur->pcb->main_thread->tid = -1;
    cur->pcb->main_thread = cur;
  }

  pthread_exit_main();

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* free file descriptors */
  struct list_elem* e;
  struct list* fds = &cur->pcb->fds;
  for (e = list_begin(fds); e != list_end(fds);) {
    struct file_descriptor* f = list_entry(e, struct file_descriptor, elem);
    file_close(f->file);
    e = list_next(e);
    free(f);
  }

  file_close(cur->pcb->exec_file);

  /*free children*/
  struct list_elem* e2;
  struct list* children = &cur->pcb->children;
  for (e2 = list_begin(children); e2 != list_end(children);) {
    struct child_process* cp = list_entry(e2, struct child_process, elem);
    e2 = list_next(e2);
    process_wait(cp->pid);
    list_remove(&cp->elem);
    free(cp);
  }

  struct list* locks = &cur->pcb->locks;
  for (e = list_begin(locks); e != list_end(locks);) {
    struct user_lock* lock = list_entry(e, struct user_lock, elem);
    e = list_next(e);
    free(lock);
  }

  struct list* semas = &cur->pcb->semas;
  for (e = list_begin(semas); e != list_end(semas);) {
    struct user_sema* sema = list_entry(e, struct user_sema, elem);
    e = list_next(e);
    free(sema);
  }

  struct list* pthreads = &cur->pcb->pthreads;
  for (e = list_begin(pthreads); e != list_end(pthreads);) {
    struct pthread* p = list_entry(e, struct pthread, elem);
    e = list_next(e);
    free(p);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
  struct child_process* cp = cur->pcb->child_ptr;

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;

  free(pcb_to_free);
  sema_up(&cp->wait_sema);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);

  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);
  t->pcb->exec_file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
static bool setup_thread(void (**eip)(void), void** esp, stub_fun sf) {
  uint8_t* kpage;
  bool success = false;
  struct process* pcb = thread_current()->pcb;

  uint8_t* stack = PHYS_BASE - PGSIZE;

  /* allocate new thread at end of last thread */
  if (!list_empty(&pcb->pthreads)) {
    struct pthread* end = list_entry(list_back(&pcb->pthreads), struct pthread, elem);
    stack = end->stack - PGSIZE;
  }

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(stack - PGSIZE, kpage, true);
    if (success)
      *esp = stack;
    else
      palloc_free_page(kpage);
  }

  *eip = (void (*)(void))sf;
  return success;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {

  struct pthread_data* pd = malloc(sizeof(struct pthread_data));
  if (pd == NULL) {
    return TID_ERROR;
  }
  struct pthread* pt = malloc(sizeof(struct pthread));
  if (pt == NULL) {
    free(pd);
    return TID_ERROR;
  }

  pd->sf = sf;
  pd->tf = tf;
  pd->arg = arg;
  struct process* pcb = thread_current()->pcb;
  pd->pthread = pt;
  sema_init(&pd->sema, 0);
  pd->success = false;
  pt->stack = NULL;
  pt->wait = false;
  pt->tid = TID_ERROR;
  sema_init(&pt->wait_sema, 0);
  tid_t tid = thread_create(pcb->process_name, PRI_DEFAULT, start_pthread, pd);
  if (tid == TID_ERROR) {
    free(pd);
    free(pt);
    return TID_ERROR;
  }
  sema_down(&pd->sema);
  if (!pd->success) {
    free(pd);
    free(pt);
    return TID_ERROR;
  }
  return tid;
}
static void fill_stub_args(void** esp, pthread_fun tf, void* arg) {
  uint8_t* stack = *esp;
  /* 16 bytes align and 4 bytes for return address */
  stack -= 20;
  *esp = stack;
  /* return address */
  *((uint32_t*)stack) = 0;
  /* tf */
  stack += 4;
  *((uint32_t*)stack) = (uint32_t)tf;
  /* arg */
  stack += 4;
  *((uint32_t*)stack) = (uint32_t)arg;
}
/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_) {
  struct pthread_data* pd = exec_;
  struct intr_frame if_;

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  asm volatile("fninit; fsave (%0)" : : "g"(&if_.fpu));
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  process_activate();

  struct thread* cur = thread_current();
  struct process* pcb = cur->pcb;

  struct pthread* pt = pd->pthread;
  pt->tid = cur->tid;

  lock_acquire(&pcb->pthreads_lock);
  pd->success = setup_thread(&if_.eip, &if_.esp, pd->sf);
  if (!pd->success) {
    lock_release(&pcb->pthreads_lock);
    sema_up(&pd->sema);
    thread_exit();
  }
  pt->stack = if_.esp;
  list_push_back(&pcb->pthreads, &pt->elem);
  lock_release(&pcb->pthreads_lock);

  fill_stub_args(&if_.esp, pd->tf, pd->arg);
  sema_up(&pd->sema);

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

static struct pthread* find_pthread(tid_t tid) {
  struct thread* cur = thread_current();
  struct list_elem* e;
  for (e = list_begin(&cur->pcb->pthreads); e != list_end(&cur->pcb->pthreads); e = list_next(e)) {
    struct pthread* pt = list_entry(e, struct pthread, elem);
    if (pt->tid == tid) {
      return pt;
    }
  }
  return NULL;
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
  struct thread* cur = thread_current();
  if (cur->tid == tid) {
    return -1;
  }
  if (tid == cur->pcb->main_thread->tid) {
    sema_down(&cur->pcb->main_wait);
    return tid;
  }
  struct pthread* pt = find_pthread(tid);
  if (pt == NULL || pt->wait) {
    return TID_ERROR;
  }
  pt->wait = true;
  sema_down(&pt->wait_sema);
  lock_acquire(&cur->pcb->pthreads_lock);
  list_remove(&pt->elem);
  lock_release(&cur->pcb->pthreads_lock);
  free(pt);
  return tid;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* cur = thread_current();
  struct process* pcb = cur->pcb;
  if (is_main_thread(cur, pcb)) {
    sema_up(&pcb->main_wait);
    pthread_exit_main();
  } else {
    lock_acquire(&pcb->pthreads_lock);
    struct pthread* pt = find_pthread(cur->tid);
    palloc_free_page(pagedir_get_page(pcb->pagedir, pt->stack - PGSIZE));
    pagedir_clear_page(pcb->pagedir, pt->stack - PGSIZE);
    lock_release(&pcb->pthreads_lock);
    sema_up(&pt->wait_sema);
    thread_exit();
  }
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* cur = thread_current();
  struct process* pcb = cur->pcb;
  struct list_elem* e;
  struct list* pthreads = &pcb->pthreads;
  for (e = list_begin(pthreads); e != list_end(pthreads);) {
    struct pthread* pt = list_entry(e, struct pthread, elem);
    e = list_next(e);
    if (pt->tid != cur->tid) {
      ASSERT(pt->wait == false);
      sema_down(&pt->wait_sema);
      lock_acquire(&cur->pcb->pthreads_lock);
      list_remove(&pt->elem);
      lock_release(&cur->pcb->pthreads_lock);
      free(pt);
    }
  }
}
