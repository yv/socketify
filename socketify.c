#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>

#ifdef __i386__
#define REG_IP(regs)   (regs.eip)
#define REG_SP(regs)   (regs.esp)
#define REG_ARG0(regs) (regs.orig_eax)
#define REG_ARG0_ACTUAL(regs) (regs.eax)
#define REG_ARG1(regs) (regs.ebx)
#define REG_ARG2(regs) (regs.ecx)
#define REG_ARG3(regs) (regs.edx)
#else
#define REG_IP(regs)   (regs.rip)
#define REG_SP(regs)   (regs.rsp)
#define REG_ARG0(regs) (regs.orig_rax)
#define REG_ARG0_ACTUAL(regs) (regs.rax)
#define REG_ARG1(regs) (regs.rdi)
#define REG_ARG2(regs) (regs.rsi)
#define REG_ARG3(regs) (regs.rdx)
#endif

#ifdef WITH_DEBUG
#define DEBUG(fmt...) fprintf(stderr, fmt...)
#else
#define DEBUG(fmt...) 0
#endif

pid_t run_program(char *argv[])
{
  pid_t chld=fork();
  int retval;
  if (chld==0) {
    ptrace(PTRACE_TRACEME, 0,0,0);
    retval=execv(argv[0],argv);
    perror("execvp failed");
    exit(1);
  } else {
    return chld;
  }
}

char status_buf[4096];
char *report_status(int status)
{
  if (WIFEXITED(status)) {
    sprintf(status_buf, "(exited %d)", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    sprintf(status_buf, "(terminated by signal %d)", WTERMSIG(status));
  } else if (WIFSTOPPED(status)) {
    sprintf(status_buf, "(stopped by signal %s)", strsignal(WSTOPSIG(status)));
  } else if (WIFCONTINUED(status)) {
    sprintf(status_buf, "(continued)");
  } else if (status==-1) {
    sprintf(status_buf, "(error: %s)", strerror(errno));
  } else {
    sprintf(status_buf, "(unknown: %d)",status);
  }
  return status_buf;
}

const int long_size = sizeof(long);

void getdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child,
                          addr + i * long_size, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child,
                          addr + i * long_size, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

void putdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKETEXT, child,
               addr + i * long_size, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKETEXT, child,
               addr + i * long_size, data.val);
    }
}

/*** from vars.c ***/
#include "vars.c"
/*** end vars.c ***/

int wait_for(pid_t process, int do_exit)
{
  int status;
  int done=0;
  while(!done)
  {
    waitpid(process, &status, 0);
    if (WIFSTOPPED(status) &&
	WSTOPSIG(status)==SIGCHLD) {
      ptrace(PTRACE_CONT, process, 0, 0);
    } else {
      done=1;
    }
  } 
  if (WIFEXITED(status)) {
    if (do_exit) {
      exit(WEXITSTATUS(status));
    }
  }
  if (WIFSIGNALED(status)) {
    fprintf(stderr, "Terminated: %s\n", strsignal(WTERMSIG(status)));
    exit(1);
  }
  return status;
}

void inject_server(pid_t traced_process)
{
  struct user_regs_struct backup_regs, new_regs;
  pid_t child_process;
  int retval, status;
  long mmap_args;
  long buf_addr;
  char backup[sizeof(insertcode)];
  ptrace(PTRACE_GETREGS, traced_process,
           0, &backup_regs);
  memcpy((void *)&new_regs, (void *)&backup_regs,
	 sizeof(struct user_regs_struct));
  // Step 1: replace a call by a mmap call
  // we abuse the child's read buffer for the
  // parameters
  assert(REG_ARG3(backup_regs)>=24);
  mmap_args=REG_ARG2(backup_regs);
  ptrace(PTRACE_POKEDATA, traced_process,
	 mmap_args, 0);
  ptrace(PTRACE_POKEDATA, traced_process,
	 mmap_args+4, sizeof(insertcode));
  ptrace(PTRACE_POKEDATA, traced_process,
	 mmap_args+8, PROT_READ|PROT_WRITE|PROT_EXEC);
  ptrace(PTRACE_POKEDATA, traced_process,
	 mmap_args+12, MAP_PRIVATE|MAP_ANONYMOUS);
  ptrace(PTRACE_POKEDATA, traced_process,
	 mmap_args+16, -1);
  ptrace(PTRACE_POKEDATA, traced_process,
	 mmap_args+20, 0);
  REG_ARG0(new_regs)=SYS_mmap;
  REG_ARG1(new_regs)=mmap_args;
  ptrace(PTRACE_SETREGS, traced_process,
           0, &new_regs);
  retval=ptrace(PTRACE_SYSCALL, traced_process, 0, 0);
  if (retval!=0) {
    perror("PTRACE_SYSCALL (2)");
    exit(1);
  }
  wait_for(traced_process, 1);
  // Step 2: put actual code in place and run it
  // adjust EIP so that it points to the original
  // read() syscall
  ptrace(PTRACE_GETREGS, traced_process,
           NULL, &new_regs);
  DEBUG("mmap returned %lx\n",
	REG_ARG0_ACTUAL(new_regs));
  buf_addr=REG_ARG0_ACTUAL(new_regs);
  putdata(traced_process, buf_addr,
	  insertcode, sizeof(insertcode));
  // assume that it's an int 0x80
  assert(0x80cd ==
	 (0xffff & ptrace(PTRACE_PEEKDATA, traced_process,
			  REG_IP(backup_regs)-2,0)));
  REG_IP(backup_regs) -= 2;
  REG_SP(backup_regs) -= 4;
  ptrace(PTRACE_POKEDATA, traced_process,
	 REG_SP(backup_regs), REG_IP(backup_regs));
  backup_regs.eax=backup_regs.orig_eax;
  REG_IP(backup_regs)=buf_addr;
  
  ptrace(PTRACE_SETREGS, traced_process,
           NULL, &backup_regs);
    ptrace(PTRACE_CONT, traced_process, 0, 0);
  ptrace(PTRACE_DETACH, traced_process, 0, 0);
}

int main(int argc, char *argv[])
{
  char **args=malloc(argc*sizeof(char *));
  pid_t traced_process;
  struct user_regs_struct regs;
  int status, retval;
  int need_read=0;
  int i;
  while (argv[1][0]=='-') {
    if (argv[1][1]=='p') {
      assert(argc>2);
      ((struct sockaddr_in *)(insertcode+offset_bindaddr))->sin_port =
	htons(atoi(argv[2]));
      argc -= 2;
      argv += 2;
    } else if (argv[1][1]=='b') {
      assert(argc>2);
      ((struct sockaddr_in *)(insertcode+offset_bindaddr))->sin_addr.s_addr =
	inet_addr(argv[2]);
      argc -= 2;
      argv += 2;
    }
  }
  for (i=1; i<argc; i++) {
    args[i-1]=argv[i];
  }
  args[argc-1]=0;
  traced_process=run_program(args);
  DEBUG("after fork, pid=%d\n", traced_process);
  waitpid(traced_process, &status, 0);
  while (1) {
    retval=ptrace(PTRACE_SYSCALL, traced_process, 0, 0);
    if (retval!=0) {
      perror("PTRACE_SYSCALL");
      exit(1);
    }
    waitpid(traced_process, &status, 0);
    if (WIFEXITED(status)) {
      exit(WEXITSTATUS(status));
    }
    retval=ptrace(PTRACE_GETREGS, traced_process, 0, &regs);
    if (retval!=0) {
      perror("PTRACE_GETREGS");
      exit(1);
    }
#ifdef __i386__
    /* 32bit mode. */
    if (regs.orig_eax==3 && regs.ebx==0) {
      DEBUG("read from stdin!!!\n");
      inject_server(traced_process);
    }
#else
    if (regs.cs == 0x33) {
      /* 64bit mode. ignore */
      if (regs.orig_rax==3 && regs.rdi==0) {
	fprintf(stderr, "read from stdin in 64bit mode (ignored)\n");
	need_read=0;
      }
    } else if (regs.cs == 0x23) {
      /* 32bit mode. */
      if (regs.orig_rax==3 && regs.rbx==0) {
	fprintf(stderr, "read from stdin!!!\n");
	inject_server(traced_process);
      }
    }
#endif
    ptrace(PTRACE_SYSCALL, traced_process, 0, 0);
    if (retval!=0) {
      perror("PTRACE_SYSCALL (2)");
      exit(1);
    }
    waitpid(traced_process, &status, 0);
    if (WIFEXITED(status)) {
      exit(WEXITSTATUS(status));
    }
  }
}
