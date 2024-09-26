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
    default:
      error_exit();
  }
}
