#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <float.h>

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void error_exit() {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
  process_exit();
}

static void is_valid_pointer(const void* pointer) {
  if (pointer == NULL || !is_user_vaddr(pointer) ||
      pagedir_get_page(thread_current()->pcb->pagedir, pointer) == NULL) {
    error_exit();
  }
}

static void validate_pointer(void* pointer, size_t size) {
  char* _pointer = (char*)pointer;
  for (size_t i = 0; i < size; i++) {
    is_valid_pointer(_pointer + i);
  }
}

static void validate_string(const char* string) {
  is_valid_pointer(string);
  while (*string != '\0') {
    string++;
    is_valid_pointer(string);
  }
}

static void validate_args(uint32_t* args, int num_args) {
  for (int i = 0; i < num_args; i++) {
    validate_pointer(args + i, sizeof(uint32_t));
  }
}

static void validate_buffer(void* buffer, unsigned size) {
  for (unsigned i = 0; i < size; i++) {
    is_valid_pointer(buffer + i);
  }
}

static void sys_open(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  char* file_name = (char*)args[1];
  lock_acquire(&thread_current()->pcb->fds_lock);
  struct file* file = filesys_open(file_name);
  if (file == NULL) {
    f->eax = -1;
    lock_release(&thread_current()->pcb->fds_lock);
    return;
  }
  struct file_descriptor* fdp = malloc(sizeof(struct file_descriptor));
  if (fdp == NULL) {
    file_close(file);
    f->eax = -1;
    lock_release(&thread_current()->pcb->fds_lock);
    return;
  }
  struct list* fds = &thread_current()->pcb->fds;
  int fd = 2;
  if (!list_empty(fds)) {
    struct file_descriptor* last = list_entry(list_back(fds), struct file_descriptor, elem);
    fd = last->fd + 1;
  }
  fdp->fd = fd;
  fdp->file = file;
  lock_init(&fdp->lock);
  list_push_back(fds, &fdp->elem);
  f->eax = fd;
  lock_release(&thread_current()->pcb->fds_lock);
}

static struct file_descriptor* get_fd(int fd) {
  if (fd < 2) {
    return NULL;
  }
  lock_acquire(&thread_current()->pcb->fds_lock);
  struct list* fds = &thread_current()->pcb->fds;
  struct list_elem* e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
    struct file_descriptor* fdp = list_entry(e, struct file_descriptor, elem);
    if (fdp->fd == fd) {
      lock_release(&thread_current()->pcb->fds_lock);
      return fdp;
    }
  }
  lock_release(&thread_current()->pcb->fds_lock);
  return NULL;
}

static void sys_close(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd = args[1];
  struct file_descriptor* fdp = get_fd(fd);
  if (fdp == NULL) {
    f->eax = -1;
    return;
  }
  lock_acquire(&fdp->lock);
  file_close(fdp->file);
  lock_release(&fdp->lock);
  lock_acquire(&thread_current()->pcb->fds_lock);
  list_remove(&fdp->elem);
  free(fdp);
  lock_release(&thread_current()->pcb->fds_lock);
}

static void sys_filesize(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd = args[1];
  struct file_descriptor* fdp = get_fd(fd);
  if (fdp == NULL) {
    f->eax = -1;
    return;
  }
  lock_acquire(&fdp->lock);
  f->eax = file_length(fdp->file);
  lock_release(&fdp->lock);
}

static void sys_read(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd = args[1];
  void* buffer = (void*)args[2];
  unsigned size = args[3];
  if (fd == STDIN_FILENO) {

    for (unsigned i = 0; i < size; i++) {
      ((char*)buffer)[i] = input_getc();
    }
    f->eax = size;
    return;
  }
  struct file_descriptor* fdp = get_fd(fd);
  if (fdp == NULL) {
    f->eax = -1;
    return;
  }
  lock_acquire(&fdp->lock);
  f->eax = file_read(fdp->file, buffer, size);
  lock_release(&fdp->lock);
}

static void sys_write(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd = args[1];
  void* buffer = (void*)args[2];
  unsigned size = args[3];
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->eax = size;
    return;
  }
  struct file_descriptor* fdp = get_fd(fd);
  if (fdp == NULL) {
    f->eax = -1;
    return;
  }
  lock_acquire(&fdp->lock);
  f->eax = file_write(fdp->file, buffer, size);
  lock_release(&fdp->lock);
}

static void sys_seek(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd = args[1];
  unsigned position = args[2];
  struct file_descriptor* fdp = get_fd(fd);
  if (fdp == NULL) {
    return;
  }
  lock_acquire(&fdp->lock);
  file_seek(fdp->file, position);
  lock_release(&fdp->lock);
}

static void sys_tell(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd = args[1];
  struct file_descriptor* fdp = get_fd(fd);
  if (fdp == NULL) {
    f->eax = -1;
    return;
  }
  lock_acquire(&fdp->lock);
  f->eax = file_tell(fdp->file);
  lock_release(&fdp->lock);
}

static void sys_pthread_create(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  stub_fun sfun = (stub_fun)args[1];
  pthread_fun tfun = (pthread_fun)args[2];
  const void* arg = (const void*)args[3];
  f->eax = pthread_execute(sfun, tfun, arg);
}

static void sys_pthread_exit(struct intr_frame* f) {
  pthread_exit();
  if (is_main_thread(thread_current(), thread_current()->pcb)) {
    f->eax = 0;
    if (thread_current()->tid == -1) {
      thread_exit();
    }
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, 0);
    process_exit();
  }
  NOT_REACHED();
}

static void sys_pthread_join(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  tid_t tid = args[1];
  f->eax = pthread_join(tid);
}

static void sys_lock_init(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  lock_t* lock = (lock_t*)args[1];
  if (lock == NULL) {
    f->eax = false;
    return;
  }

  struct user_lock* u_lock = malloc(sizeof(struct user_lock));
  lock_init(&u_lock->lock);
  if (u_lock == NULL) {
    f->eax = false;
    return;
  }
  int id = 0;
  struct process* pcb = thread_current()->pcb;
  struct list* u_locks = &pcb->locks;
  lock_acquire(&pcb->pthreads_lock);
  if (!list_empty(u_locks)) {
    struct user_lock* end = list_entry(list_back(u_locks), struct user_lock, elem);
    id = end->id + 1;
  }
  u_lock->id = id;
  list_push_back(&pcb->locks, &u_lock->elem);
  lock_release(&pcb->pthreads_lock);
  *lock = id;
  f->eax = true;
}

static struct user_lock* find_user_lock(lock_t u_lock) {
  struct list_elem* e;
  struct list* locks = &thread_current()->pcb->locks;
  for (e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
    struct user_lock* l = list_entry(e, struct user_lock, elem);
    if (l->id == u_lock) {
      return l;
    }
  }
  return NULL;
};

static void sys_lock_acquire(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  lock_t* lock = (lock_t*)args[1];

  struct process* pcb = thread_current()->pcb;
  /* get user lock */
  struct user_lock* u_lock = NULL;
  lock_acquire(&pcb->pthreads_lock);
  u_lock = find_user_lock(*lock);
  lock_release(&pcb->pthreads_lock);
  /* lock not valid or acquire failed */
  if (u_lock == NULL || lock_held_by_current_thread(&u_lock->lock)) {
    f->eax = false;
    return;
  }
  lock_acquire(&u_lock->lock);
  f->eax = true;
}

static void sys_lock_release(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  lock_t* lock = (lock_t*)args[1];

  struct process* pcb = thread_current()->pcb;
  /* get user lock */
  struct user_lock* u_lock = NULL;
  lock_acquire(&pcb->pthreads_lock);
  u_lock = find_user_lock(*lock);
  lock_release(&pcb->pthreads_lock);
  /* lock not valid or acquire failed */
  if (u_lock == NULL || !lock_held_by_current_thread(&u_lock->lock)) {
    f->eax = false;
    return;
  }
  lock_release(&u_lock->lock);
  f->eax = true;
}

static void sys_sema_init(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  sema_t* sema = (sema_t*)args[1];
  int val = args[2];
  if (sema == NULL || val < 0) {
    f->eax = false;
    return;
  }

  struct user_sema* u_sema = malloc(sizeof(struct user_sema));
  sema_init(&u_sema->sema, val);
  if (u_sema == NULL || val < 0) {
    f->eax = false;
    return;
  }
  int id = 0;
  struct process* pcb = thread_current()->pcb;
  struct list* u_semas = &pcb->semas;
  lock_acquire(&pcb->pthreads_lock);
  if (!list_empty(u_semas)) {
    struct user_sema* end = list_entry(list_back(u_semas), struct user_sema, elem);
    id = end->id + 1;
  }
  u_sema->id = id;
  list_push_back(&pcb->semas, &u_sema->elem);
  lock_release(&pcb->pthreads_lock);
  *sema = id;
  f->eax = true;
}

static struct user_sema* find_user_sema(sema_t u_sema) {
  struct list_elem* e;
  struct list* semas = &thread_current()->pcb->semas;
  for (e = list_begin(semas); e != list_end(semas); e = list_next(e)) {
    struct user_sema* l = list_entry(e, struct user_sema, elem);
    if (l->id == u_sema) {
      return l;
    }
  }
  return NULL;
};

static void sys_sema_down(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  sema_t* sema = (sema_t*)args[1];

  struct process* pcb = thread_current()->pcb;
  /* get user sema */
  struct user_sema* u_sema = NULL;
  lock_acquire(&pcb->pthreads_lock);
  u_sema = find_user_sema(*sema);
  lock_release(&pcb->pthreads_lock);
  /* sema not valid or acquire failed */
  if (u_sema == NULL) {
    f->eax = false;
    return;
  }
  sema_down(&u_sema->sema);
  f->eax = true;
}

static void sys_sema_up(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  sema_t* sema = (sema_t*)args[1];
  struct process* pcb = thread_current()->pcb;
  /* get user sema */
  struct user_sema* u_sema = NULL;
  lock_acquire(&pcb->pthreads_lock);
  u_sema = find_user_sema(*sema);
  lock_release(&pcb->pthreads_lock);
  /* sema not valid or acquire failed */
  if (u_sema == NULL) {
    f->eax = false;
    return;
  }
  sema_up(&u_sema->sema);
  f->eax = true;
}

static void sys_get_tid(struct intr_frame* f) { f->eax = thread_current()->tid; }

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  validate_pointer(args, sizeof(uint32_t));

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  // if (!validate_pointer(args, sizeof(uint32_t))) {
  //   f -> eax = -1;
  //   printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
  //   process_exit();
  // }
  switch (args[0]) {
    case SYS_EXIT:
      validate_args(args, 2);
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      thread_current()->pcb->child_ptr->exit_status = args[1];
      process_exit();
      break;
    case SYS_PRACTICE:
      validate_args(args, 2);
      f->eax = args[1] + 1;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXEC:
      validate_args(args, 2);
      validate_string((char*)args[1]);
      f->eax = process_execute((char*)args[1]);
      break;
    case SYS_WAIT:
      validate_args(args, 2);
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      validate_args(args, 3);
      validate_string((char*)args[1]);
      if (args[2] < 0 || args[1] == "") {
        f->eax = false;
      } else {
        f->eax = filesys_create((char*)args[1], args[2]);
      }
      break;
    case SYS_REMOVE:
      validate_args(args, 2);
      validate_string((char*)args[1]);
      if (args[1] == "") {
        f->eax = false;
      } else {
        f->eax = filesys_remove((char*)args[1]);
      }
      break;
    case SYS_OPEN:
      validate_args(args, 2);
      validate_string((char*)args[1]);
      sys_open(f);
      break;
    case SYS_FILESIZE:
      validate_args(args, 2);
      sys_filesize(f);
      break;
    case SYS_READ:
      validate_args(args, 4);
      validate_pointer((void*)args[2], args[3]);
      validate_buffer((void*)args[2], args[3]);
      sys_read(f);
      break;
    case SYS_CLOSE:
      validate_args(args, 2);
      sys_close(f);
      break;
    case SYS_WRITE:
      validate_args(args, 4);
      validate_pointer((void*)args[2], args[3]);
      validate_buffer((void*)args[2], args[3]);
      sys_write(f);
      break;
    case SYS_SEEK:
      validate_args(args, 3);
      sys_seek(f);
      break;
    case SYS_TELL:
      validate_args(args, 2);
      sys_tell(f);
      break;
    case SYS_COMPUTE_E:
      validate_args(args, 2);
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_PT_CREATE:
      validate_args(args, 4);
      sys_pthread_create(f);
      break;
    case SYS_PT_EXIT:
      validate_args(args, 1);
      sys_pthread_exit(f);
      break;
    case SYS_PT_JOIN:
      validate_args(args, 2);
      sys_pthread_join(f);
      break;
    case SYS_LOCK_INIT:
      validate_args(args, 2);
      sys_lock_init(f);
      break;
    case SYS_LOCK_ACQUIRE:
      validate_args(args, 2);
      sys_lock_acquire(f);
      break;
    case SYS_LOCK_RELEASE:
      validate_args(args, 2);
      sys_lock_release(f);
      break;
    case SYS_SEMA_INIT:
      validate_args(args, 3);
      sys_sema_init(f);
      break;
    case SYS_SEMA_DOWN:
      validate_args(args, 2);
      sys_sema_down(f);
      break;
    case SYS_SEMA_UP:
      validate_args(args, 2);
      sys_sema_up(f);
      break;
    case SYS_GET_TID:
      validate_args(args, 1);
      sys_get_tid(f);
      break;
    default:
      error_exit();
  }
}
