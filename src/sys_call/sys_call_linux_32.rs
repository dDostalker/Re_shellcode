pub mod _0_restart_syscall;
mod _100_fstatfs;
mod _101_ioperm;
pub mod _102_socketcall;
mod _103_syslog;
mod _104_setitimer;
mod _105_getitimer;
mod _106_stat;
mod _107_lstat;
mod _108_fstat;
mod _109_olduname;
mod _10_unlink;
mod _110_iopl;
mod _111_vhangup;
mod _112_idle;
mod _113_vm86old;
mod _114_wait4;
mod _115_swapoff;
mod _116_sysinfo;
mod _117_ipc;
mod _119_sigreturn;
mod _11_execve;
mod _120_clone;
mod _121_setdomainname;
mod _122_uname;
mod _123_modify_ldt;
mod _124_adjtimex;
pub mod _125_mprotect;
mod _126_sigprocmask;
mod _127_create_module;
mod _128_init_module;
mod _129_delete_module;
mod _12_chdir;
mod _130_get_kernel_syms;
mod _131_quotactl;
mod _132_getpgid;
mod _133_fchdir;
mod _134_bdflush;
mod _135_sysfs;
mod _136_personality;
mod _137_afs_syscall;
mod _138_setfsuid;
mod _139_setfsgid;
mod _13_time;
mod _140__llseek;
mod _141_getdents;
mod _142__newselect;
mod _143_flock;
mod _144_msync;
mod _145_readv;
mod _146_writev;
mod _147_getsid;
mod _148_fdatasync;
mod _149__sysctl;
mod _14_mknod;
mod _150_mlock;
mod _151_munlock;
mod _152_mlockall;
mod _153_munlockall;
mod _154_sched_setparam;
mod _155_sched_getparam;
mod _156_sched_setscheduler;
mod _157_sched_getcheduler;
mod _158_sched_yield;
mod _159_sched_get_priority_max;
mod _160_sched_get_priority_min;
mod _161_sched_rr_get_interval;
mod _162_nanosleep;
mod _163_mremap;
mod _164_setresuid;
mod _165_getresuid;
mod _166_vm86;
mod _167_query_module;
mod _168_poll;
mod _169_nfsservctl;
mod _16_lchown;
mod _170_setresgid;
mod _171_getresgid;
mod _172_prctl;
mod _173_rt_sigreturn;
mod _174_sigaction;
mod _175_rt_sigprocmask;
mod _176_rt_sigpending;
mod _177_rt_sigtimedwait;
mod _178_rt_sigqeueinfo;
mod _179_rt_sifsuspend;
mod _17_break;
mod _180_pread64;
mod _181_pwrite64;
mod _182_chown;
mod _183_getcwd;
mod _184_capget;
mod _185_capset;
mod _186_sigaltstack;
mod _187_sendfile;
mod _188_getpmsg;
mod _189_putpmsg;
mod _18_oldstat;
mod _190_vfork;
mod _191_ugetrlimit;
mod _192_mmap2;
mod _193_truncate64;
mod _194_ftruncate64;
mod _195_stat64;
mod _196_lstat64;
mod _197_fstat64;
mod _198_lchown32;
mod _199_getuid32;
mod _19_lseek;
pub mod _1_exit;
mod _200_getgid32;
mod _201_geteuid32;
mod _202_getegid32;
mod _203_setregid;
mod _204_setregid32;
mod _205_getgroups32;
mod _206_setgroups32;
mod _207_fchown32;
mod _208_setresuid32;
mod _209_getresuid32;
mod _20_getpid;
mod _211_getresgid32;
mod _212_chown32;
mod _213_setuid32;
mod _214_setgid32;
mod _215_setfsuid32;
mod _216_6setfsgid32;
mod _217_pivot_root;
mod _218_mincore;
mod _219_madvise;
mod _21_mount;
mod _220_getdents64;
mod _221_fcntl64;
mod _224_gettid;
mod _225_readahead;
mod _226_setxattr;
mod _227_lsetxattr;
mod _228_fsetxattr;
mod _229_getxattr;
mod _22_umount;
mod _230_lgetxattr;
mod _231_fgetxattr;
mod _232_listxattr;
mod _233_llistxattr;
mod _234_flistxattr;
mod _235_removexattr;
mod _236_lremovexattr;
mod _237_fremovexattr;
mod _238_tkill;
mod _239_sendfile64;
mod _23_setuid;
mod _240_futex;
mod _241_sched_setaffinity;
mod _242_sched_getaffinity;
mod _243_set_thread_area;
mod _244_get_thread_area;
mod _245_io_setup;
mod _246_io_destroy;
mod _247_io_getevents;
mod _248_io_submit;
mod _249_io_cancel;
mod _24_getuid;
mod _250_fadvise64;
mod _252_exit_group;
mod _253_lookup_dcookie;
mod _254_epoll_create;
mod _255_epoll_ctl;
mod _256_epoll_wait;
mod _25_stime;
mod _26_ptrace;
mod _27_alarm;
mod _28_oldfstat;
mod _29_pause;
pub mod _2_fork;
mod _30_utime;
mod _31_stty;
mod _32_gtty;
mod _33_access;
mod _34_nice;
mod _35_ftime;
mod _36_sync;
mod _37_kill;
mod _38_rename;
mod _39_mkdir;
pub mod _3_read;
mod _40_rmdir;
mod _41_dup;
mod _42_pipe;
mod _43_times;
mod _44_prof;
mod _45_brk;
mod _46_setgid;
mod _47_getgid;
mod _48_signal;
mod _49_geteuid;
mod _4_write;
mod _50_getegid;
mod _51_acct;
mod _52_umount2;
mod _53_lock;
mod _54_ioctl;
mod _55_fcntl;
mod _56_mpx;
mod _57_setpgid;
mod _58_ulimit;
mod _59_oldolduname;
mod _5_open;
mod _60_umask;
mod _61_chroot;
mod _62_ustat;
mod _63_dup2;
mod _64_getppid;
mod _65_getpgrp;
mod _66_setsid;
mod _67_sigaction;
mod _68_sgetmask;
mod _69_ssetmask;
mod _6_close;
mod _70_setreuid;
mod _71_setregid;
mod _72_sigsuspend;
mod _73_sigpending;
mod _74_sethostname;
mod _75_setrlimit;
mod _76_getrlimit;
mod _77_getrusage;
mod _78_gettimeofday;
mod _79_settimeofday;
mod _7_waitpid;
mod _80_getgroups;
mod _81_setgroups;
mod _82_select;
mod _83_symlink;
mod _84_oldlstat;
mod _85_readlink;
mod _86_uselib;
mod _87_swapon;
mod _88_reboot;
mod _89_readir;
mod _8_creat;
mod _90_mmap;
mod _91_munmap;
mod _92_truncate;
mod _93_ftruncate;
mod _94_fchmod;
mod _95_fchown;
mod _96_getpriority;
mod _97_setpriority;
mod _98_profil;
mod _99_statfs;
mod _9_link;