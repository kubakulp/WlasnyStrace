#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h> /* for ptrace() */
#include <sys/reg.h>    /* for RAX */
#include <sys/wait.h>   /* for SIGSTOP */
#include <sys/user.h>   /* for struct user_regs_struct */

int wait_for_syscall(pid_t child) /* funckja oczekujaca na sygnal */
{
    int status;
    for(;;)
    {
        ptrace(PTRACE_SYSCALL, child, 0, 0); /* wznawia wykonanie procesu sledzonego */
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            return 0;
        }
        if (WIFEXITED(status))
        {
            return 1;
        }
    }
}

int do_trace(pid_t child)
{
    int status, syscall, retval;
    struct user_regs_struct regs;

    char *syscalls[314] ={"read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64",
    "pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid",
    "sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve",
    "exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename",
    "mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid",
    "setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid",
    "getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority",
    "setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall",
    "munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname",
    "setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid",
    "readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex",
    "sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old",
    "remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime",
    "clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive",
    "mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat",
    "mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list",
    "get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4",
    "signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64",
    "name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module"};

    int syscallsArg[314] = {3,3,3,1,2,2,2,3,3,6,3,2,1,4,4,0,3,4,4,3,3,2,1,5,0,1,3,3,3,3,3,3,1,2,0,2,2,1,3,0,4,3,3,3,6,6,3,3,2,3,2,3,3,4,5,5,
                            5,0,0,3,1,4,2,1,3,3,4,1,2,4,5,3,3,2,1,1,2,2,3,2,1,1,2,2,1,2,2,1,2,3,2,2,3,3,3,1,2,2,2,1,1,4,0,3,0,1,1,0,0,2,0,0,
                            0,2,2,2,2,3,3,3,3,1,1,1,1,2,2,2,4,3,2,2,2,3,1,1,2,2,2,3,2,3,2,2,3,1,1,1,2,2,2,1,0,0,3,2,1,5,3,1,2,1,0,1,2,5,2,2,
                            1,4,2,2,1,3,0,3,2,0,0,4,0,0,0,0,0,0,0,3,5,5,5,4,4,4,3,3,3,2,2,2,2,1,6,3,3,1,2,1,5,3,3,1,3,1,0,0,5,3,1,0,4,4,3,4,
                            2,1,1,2,2,2,4,1,4,4,3,2,0,6,3,5,4,1,5,5,2,3,4,5,5,4,5,3,2,0,3,2,4,4,3,4,5,3,4,3,4,5,3,4,3,3,6,5,1,2,3,6,4,4,4,
                            6,4,6,3,2,1,4,4,2,4,4,2,1,3,2,1,5,5,4,5,5,2,5,4,5,3,2,1,4,2,3,6,6,5,3};

    char c='c';
    char w='w';
    char i='i';
    char l='l';
    char syscallsArgType[314][6] ={{i,c,w,c,c,c},{i,c,w,c,c,c},{c,i,w,c,c,c},{i,c,c,c,c,c},{c,w,c,c,c,c},{i,w,c,c,c,c},{c,w,c,c,c,c},{w,i,i,c,c,c},{i,w,i,c,c,c},{l,l,l,l,l,l},{l,w,l,c,c,c},
    {l,w,c,c,c,c},{l,c,c,c,c,c},{i,w,w,w,c,c},{i,w,w,w,c,c},{c,c,c,c,c,c},{i,i,l,c,c,c},{i,c,w,w,c,c},{i,c,w,w,c,c},{l,w,l,c,c,c},{l,w,l,c,c,c},{c,i,c,c,c,c},{i,c,c,c,c,c},{i,w,w,w,w,c},
    {c,c,c,c,c,c},{l,c,c,c,c,c},{l,w,i,c,c,c},{l,w,c,c,c,c},{l,w,i,c,c,c},{w,w,i,c,c,c},{i,c,i,c,c,c},{i,i,w,c,c,c},{i,c,c,c,c,c},{i,i,c,c,c,c},{c,c,c,c,c,c},{w,w,c,c,c,c},{i,w,c,c,c,c},
    {i,c,c,c,c,c},{i,w,w,c,c,c},{c,c,c,c,c,c},{i,i,w,w,c,c},{i,i,i,c,c,c},{i,w,i,c,c,c},{i,w,i,c,c,c},{i,w,w,i,w,i},{i,w,w,i,w,i},{i,w,i,c,c,c},{i,w,i,c,c,c},{i,i,c,c,c,c},{i,w,i,c,c,c},
    {i,i,c,c,c,c},{i,w,i,c,c,c},{i,w,i,c,c,c},{i,i,i,i,c,c},{i,i,i,c,i,c},{i,i,i,c,i,c},{l,l,i,i,i,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{i,c,c,c,c,c},{w,i,i,w,c,c},{w,i,c,c,c,c},
    {w,c,c,c,c,c},{w,i,i,c,c,c},{i,w,w,c,c,c},{i,i,i,l,c,c},{c,c,c,c,c,c},{w,i,c,c,c,c},{i,w,w,i,c,c},{i,w,w,w,i,c},{i,i,w,c,c,c},{i,i,l,c,c,c},{i,i,c,c,c,c},{i,c,c,c,c,c},{i,c,c,c,c,c},
    {c,w,c,c,c,c},{i,l,c,c,c,c},{i,w,i,c,c,c},{c,l,c,c,c,c},{c,c,c,c,c,c},{i,c,c,c,c,c},{c,c,c,c,c,c},{c,w,c,c,c,c},{c,c,c,c,c,c},{c,w,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},
    {c,c,i,c,c,c},{c,w,c,c,c,c},{i,w,c,c,c,c},{c,w,w,c,c,c},{i,w,w,c,c,c},{c,w,w,c,c,c},{i,c,c,c,c,c},{w,w,c,c,c,c},{i,w,c,c,c,c},{i,w,c,c,c,c},{w,c,c,c,c,c},{w,c,c,c,c,c},{w,w,l,l,c,c},
    {c,c,c,c,c,c},{i,c,i,c,c,c},{c,c,c,c,c,c},{w,c,c,c,c,c},{w,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{w,w,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},
    {i,w,c,c,c,c},{i,w,c,c,c,c},{w,w,w,c,c,c},{w,w,w,c,c,c},{w,w,w,c,c,c},{w,w,w,c,c,c},{w,c,c,c,c,c},{w,c,c,c,c,c},{w,c,c,c,c,c},{w,c,c,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},
    {w,w,w,w,c,c},{w,i,w,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},{c,w,c,c,c,c},{c,w,w,c,c,c},{c,c,c,c,c,c},{i,c,c,c,c,c},{w,w,c,c,c,c},{c,w,c,c,c,c},{i,w,c,c,c,c},{i,l,l,c,c,c},{i,i,c,c,c,c},
    {i,i,i,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},{w,i,w,c,c,c},{w,c,c,c,c,c},{i,c,c,c,c,c},{i,c,c,c,c,c},{w,w,c,c,c,c},{l,w,c,c,c,c},{l,w,c,c,c,c},{i,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},
    {i,w,l,c,c,c},{c,c,c,c,c,c},{w,c,c,c,c,c},{i,l,l,l,l,c},{c,c,c,c,c,c},{w,c,c,c,c,c},{i,w,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{w,w,c,c,c,c},{c,c,c,l,w,c},{c,i,c,c,c,c},
    {c,i,c,c,c,c},{c,c,c,c,c,c},{i,i,i,w,c,c},{c,i,c,c,c,c},{c,i,c,c,c,c},{i,c,c,c,c,c},{l,l,i,c,c,c},{c,c,c,c,c,c},{w,l,c,c,c,c},{c,i,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{i,c,w,w,c,c},
    {c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{i,w,w,c,c,c},{c,c,w,w,i,c},{c,c,w,w,i,c},{i,c,w,w,i,c},{c,c,w,w,c,c},{c,c,w,w,c,c},
    {i,c,w,w,c,c},{c,c,w,c,c,c},{c,c,w,c,c,c},{i,c,w,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{i,c,c,c,c,c},{w,i,c,c,c,c},{w,c,c,c,c,c},{w,i,w,w,w,w},{w,i,l,c,c,c},{w,i,l,c,c,c},{w,c,c,c,c,c},
    {w,w,c,c,c,c},{w,c,c,c,c,c},{w,l,l,w,w,c},{w,l,w,c,c,c},{w,w,w,c,c,c},{w,c,c,c,c,c},{w,c,w,c,c,c},{i,c,c,c,c,c},{c,c,c,c,c,c},{c,c,c,c,c,c},{l,l,l,l,l,c},{i,w,i,c,c,c},{i,c,c,c,c,c},
    {c,c,c,c,c,c},{i,w,w,w,c,c},{i,w,w,i,c,c},{w,w,w,c,c,c},{w,i,w,w,c,c},{w,w,c,c,c,c},{w,c,c,c,c,c},{w,c,c,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},{w,w,c,c,c,c},{w,i,w,w,c,c},{i,c,c,c,c,c},
    {i,w,i,i,c,c},{i,i,i,w,c,c},{w,w,i,c,c,c},{c,w,c,c,c,c},{c,c,c,c,c,c},{l,l,l,l,l,w},{i,l,l,c,c,c},{i,l,l,l,l,c},{c,i,w,w,c,c},{c,c,c,c,c,c},{w,c,w,i,w,c},{w,c,w,i,w,c},{w,w,c,c,c,c},
    {w,w,w,c,c,c},{l,l,w,l,c,c},{i,w,w,i,w,c},{c,c,w,w,w,c},{c,c,c,w,c,c},{i,l,l,l,l,c},{i,i,i,c,c,c},{i,i,c,c,c,c},{c,c,c,c,c,c},{i,c,w,c,c,c},{i,w,c,c,c,c},{w,l,l,l,c,c},{i,c,i,w,c,c},
    {i,c,w,c,c,c},{i,c,w,w,c,c},{i,c,w,w,i,c},{i,c,w,c,c,c},{i,c,w,i,c,c},{i,c,i,c,c,c},{i,c,i,c,c,c},{i,c,i,c,i,c},{c,i,c,c,c,c},{i,c,c,i,c,c},{i,c,w,c,c,c},{i,c,i,c,c,c},{i,w,w,w,w,w},
    {w,i,w,w,w,c},{l,c,c,c,c,c},{w,w,c,c,c,c},{i,w,w,c,c,c},{i,w,i,w,w,i},{i,i,w,i,c,c},{i,w,w,i,c,c},{i,w,l,i,c,c},{w,l,w,i,i,i},{i,c,w,i,c,c},{i,w,i,i,w,w},{i,w,w,c,c,c},{i,i,c,c,c,c},
    {i,c,c,c,c,c},{i,i,w,w,c,c},{i,i,w,w,c,c},{i,w,c,c,c,c},{i,w,i,i,c,c},{i,w,w,i,c,c},{i,i,c,c,c,c},{i,c,c,c,c,c},{i,i,i,c,c,c},{i,i,c,c,c,c},{i,c,c,c,c,c},{l,w,l,l,l,c},{l,w,l,l,l,c},
    {w,w,i,w,c,c},{w,w,i,i,l,c},{i,w,i,i,w,c},{i,i,c,c,c,c},{i,i,w,i,c,c},{w,i,w,w,c,c},{i,c,w,i,i,c},{i,w,i,c,c,c},{w,w,c,c,c,c},{i,c,c,c,c,c},{i,w,i,i,c,c},{i,i,c,c,c,c},{w,w,w,c,c,c},
    {w,w,l,w,l,l},{w,w,l,w,l,l},{w,w,i,l,l,c},{i,c,i,c,c,c}};

    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD); /*PTRACE_O_TRACESYSGOOD - pozwala znacznikowi odroznic zwykle pulapki od tych spowodowanych wywolaniem systemowym*/
    for(;;)
    {
        if (wait_for_syscall(child) != 0)
        {
            break;
        }

        ptrace(PTRACE_GETREGS, child, NULL, &regs); /*przekazujemy dane do struktury regs*/
        syscall = regs.orig_rax;
        printf("%s(", syscalls[syscall]);

        if(syscallsArg[syscall]>0)
        {
            if(syscallsArgType[syscall][0]=='c')
            {
                printf("''%llX''", regs.rdi);
            }
            else if(syscallsArgType[syscall][0]=='l')
            {
                printf("%llu", regs.rdi);
            }
            else if(syscallsArgType[syscall][0]=='w')
            {
                printf("%llX", regs.rdi);
            }
            else if(syscallsArgType[syscall][0]=='i')
            {
                printf("%lli", regs.rdi);
            }
        }

        if(syscallsArg[syscall]>1)
        {
            if(syscallsArgType[syscall][1]=='c')
            {
                printf(",''%llX''", regs.rsi);
            }
            else if(syscallsArgType[syscall][1]=='l')
            {
                printf(",%llu", regs.rsi);
            }
            else if(syscallsArgType[syscall][1]=='w')
            {
                printf(",%llX", regs.rsi);
            }
            else if(syscallsArgType[syscall][1]=='i')
            {
                printf(",%lli", regs.rsi);
            }
        }
        if(syscallsArg[syscall]>2)
        {
            if(syscallsArgType[syscall][2]=='c')
            {
                printf(",''%llX''", regs.rdx);
            }
            else if(syscallsArgType[syscall][2]=='l')
            {
                printf(",%llu", regs.rdx);
            }
            else if(syscallsArgType[syscall][2]=='w')
            {
                printf(",%llX", regs.rdx);
            }
            else if(syscallsArgType[syscall][2]=='i')
            {
                printf(",%lli", regs.rdx);
            }
        }
        if(syscallsArg[syscall]>3)
        {
            if(syscallsArgType[syscall][3]=='c')
            {
                printf(",''%llX''", regs.r10);
            }
            else if(syscallsArgType[syscall][3]=='l')
            {
                printf(",%llu", regs.r10);
            }
            else if(syscallsArgType[syscall][3]=='w')
            {
                printf(",%llX", regs.r10);
            }
            else if(syscallsArgType[syscall][3]=='i')
            {
                printf(",%lli", regs.r10);
            }
        }
        if(syscallsArg[syscall]>4)
        {
            if(syscallsArgType[syscall][4]=='c')
            {
                printf(",''%llX''", regs.r8);
            }
            else if(syscallsArgType[syscall][4]=='l')
            {
                printf(",%llu", regs.r8);
            }
            else if(syscallsArgType[syscall][4]=='w')
            {
                printf(",%llX", regs.r8);
            }
            else if(syscallsArgType[syscall][4]=='i')
            {
                printf(",%lli", regs.r8);
            }
        }
        if(syscallsArg[syscall]>5)
        {
            if(syscallsArgType[syscall][5]=='c')
            {
                printf(",''%llX''", regs.r9);
            }
            else if(syscallsArgType[syscall][5]=='l')
            {
                printf(",%llu", regs.r9);
            }
            else if(syscallsArgType[syscall][5]=='w')
            {
                printf(",%llX", regs.r9);
            }
            else if(syscallsArgType[syscall][5]=='i')
            {
                printf(",%lli", regs.r9);
            }
        }
        printf(")");

        if (wait_for_syscall(child) != 0)
        {
            break;
        }
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);

        if(retval < 0)
        {
            printf("= -1 ENOENT (no such file or directory)\n");
        }
        else
        {
            printf("    = %d\n", retval);
        }
    }
    ptrace(PTRACE_CONT, child, NULL, NULL); /* umozliwiamy zakonczenie pracy naszemu procesowi */
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        perror("Podaj jeden argument aby uzyc 'strace argument'");
        exit(1);
    }

    pid_t child = fork(); /* proces kontrolujacy tworzy proces sledzony */
    if(child==-1) /* w przypadku bledu */
    {
        perror("fork");
        exit(1);
    }
    else if(child == 0) /* proces potomny */
    {
        ptrace(PTRACE_TRACEME,0,NULL,NULL); /* ustawia bit sledzenia w strukturze zadania */
        execvp(argv[1], argv+1); /* wywoluje funkcje execvp, uruchamiajac program sledzony */
    }
    else /* proces rodzica */
    {
        return do_trace(child);
    }
    exit(0);
}
