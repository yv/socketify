.set sys_exit, 1
.set sys_fork, 2
.set sys_read, 3
.set sys_write, 4
.set sys_close, 6
.set sys_waitpid, 7
.set sys_getpid, 20
.set sys_kill, 37
.set sys_dup2, 63
.set sys_socketcall, 102

.macro syscall, syscall_no
	movl \syscall_no, %eax
	int $0x80
.endm
.macro socketcall, call_no, data
	movl $sys_socketcall, %eax
	movl $\call_no, %ebx
	leal \data, %ecx
	int $0x80
.endm


.set SYS_SOCKET, 1
.set SYS_BIND, 2
.set SYS_LISTEN, 4
.set SYS_ACCEPT, 5
.set SYS_SETSOCKOPT, 14
	
.set SOCK_STREAM, 1
.set AF_INET, 2
.set PF_INET, 2
.set IPPROTO_TCP, 6
.set SOL_SOCKET, 1
.set SO_REUSEADDR, 2
.set SO_LINGER, 13
.set SIGSTOP, 19
.set WNOHANG, 1

.section .text
.globl _start

_start:	jmp startme

.section .data
startme:
	pushal
	jmp callme
entry:	popl %esi
	xor %ebx, %ebx
	leal greeting_offset(%esi), %ecx
	movl $greeting_size, %edx
	syscall $sys_write
	socketcall SYS_SOCKET, socketargs_offset(%esi)
	movl %eax, bindargs_offset(%esi)
	movl %eax, sockopt_offset(%esi)
	leal bindaddr_offset(%esi), %eax
	movl %eax, bindargs_offset+4(%esi)
	leal one_offset(%esi), %eax
	movl %eax, sockopt_offset+12(%esi)
	socketcall SYS_SETSOCKOPT, sockopt_offset(%esi)
	movl $SO_LINGER, %eax
	movl %eax, sockopt_offset+8(%esi)
	socketcall SYS_SETSOCKOPT, sockopt_offset(%esi)
	socketcall SYS_BIND, bindargs_offset(%esi)
	test %eax, %eax
	js some_error
	movl $5, %eax
	movl %eax, bindargs_offset+4(%esi)
	socketcall SYS_LISTEN, bindargs_offset(%esi)
	test %eax, %eax
	jnz some_error
	movl %eax, bindargs_offset+4(%esi)
	movl %eax, bindargs_offset+8(%esi)
accept_loop:
	socketcall SYS_ACCEPT, bindargs_offset(%esi)
	movl %eax, %ecx
	syscall $sys_fork
	testl %eax, %eax
	jz in_child
# in parent -- close the socket and restart the loop
# trap so we can intercept the pid
restarting:
	movl %ecx, %ebx
	syscall $sys_close
	movl $-1, %ebx
	xorl %ecx, %ecx
	movl $WNOHANG, %edx
wait_for_more:
	syscall $sys_waitpid
	testl %eax, %eax
	jnz wait_for_more
	jmp accept_loop
in_child:
	movl %ecx, %ebx
	xorl %ecx, %ecx
	syscall $sys_dup2
	incl %ecx
	syscall $sys_dup2
# close the extra file descriptors we're holding
	syscall $sys_close
# pretend nothing has happened and return to where we were
	popal
	ret
some_error:
	xor %ebx, %ebx
	leal errormsg_offset(%esi), %ecx
	movl $errormsg_size, %edx
	syscall $sys_write
	incl %ebx
	syscall $sys_exit
callme:	call entry
datastart:
socketargs:
	.long AF_INET
	.long SOCK_STREAM
	.long IPPROTO_TCP
.set socketargs_offset, socketargs-datastart
bindargs:
	.long 0
	.long 0
	.long 16 # length
.set bindargs_offset, bindargs-datastart
# default: bind to localhost:4445
bindaddr:
	.short AF_INET
	.short 0x5d11
	.long 0x0100007f
	.long 0 # padding
	.long 0
.set bindaddr_offset, bindaddr-datastart
sockopt_args:
	.long 0 # sockfd
	.long SOL_SOCKET
	.long SO_REUSEADDR
	.long 0 # optval
	.long 4
.set sockopt_offset, sockopt_args-datastart
sockopt_one:
	.long 1
	.long 3
.set one_offset, sockopt_one-datastart
greeting:
	.ascii "Starting socket server\n"
	.set greeting_offset, greeting-datastart
errormsg:
	.set greeting_size, errormsg-greeting
	.ascii "Some error occurred\n"
error_end:
	.set errormsg_offset, errormsg-datastart
	.set errormsg_size, error_end-errormsg
