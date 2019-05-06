#include <asm/syscall.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/timekeeping32.h>
#include <linux/types.h>
#include <linux/uaccess.h>

MODULE_LICENSE("APACHE2");
MODULE_AUTHOR("Rodrigo Alves Lima");
MODULE_DESCRIPTION("milliScope instruments the network stack.");
MODULE_VERSION("0.01");

/***************************************************************************************************
********************************************** CONNECT *********************************************
***************************************************************************************************/

#define CONNECT_BUFF_SIZE 262144
#define MAX_CONNECT_LOG_ENTRY_LEN 256

typedef struct connect_buff_entry {
    long long ts;               /* Timestamp */
    int pid;                    /* Process ID */
    int tid;                    /* Thread ID */
    int sock_fd;                /* Socket file descriptor */
    char sock_type;             /* Socket type: SOCK_STREAM (1) or SOCK_DGRAM (2) */
    unsigned short addr_family; /* Address family: AF_INET or AF_INET6 */
    unsigned int addr_v4;       /* IPv4 address (in network byte order) */
    unsigned short addr_v6[8];  /* IPv6 address (in network byte order) */
    unsigned short port;        /* Port (in network byte order) */
} t_connect_buff_entry;
static t_connect_buff_entry connect_buff[CONNECT_BUFF_SIZE];
static int connect_buff_count = 0;
static DEFINE_SPINLOCK(connect_buff_lock);

int connect_proc_read(struct file *proc, char __user *buff, unsigned long len, long long *offset) {
    char log_entry[MAX_CONNECT_LOG_ENTRY_LEN];
    int log_entry_length;
    int copied_len = 0;
    t_connect_buff_entry *buff_entry;

    /* Write CSV header. */
    if (*offset == 0) {
        log_entry_length = sprintf(log_entry, "TS,PID,TID,SOCK_FD,SOCK_TYPE,IP,PORT\n");
        copy_to_user(buff + copied_len, log_entry, log_entry_length);
        copied_len += log_entry_length;
    }

    /* Write CSV rows. */
    while (*offset < connect_buff_count && copied_len < len - MAX_CONNECT_LOG_ENTRY_LEN) {
        buff_entry = &connect_buff[*offset];
        if (buff_entry->addr_family == AF_INET)
            log_entry_length = sprintf(log_entry, "%lld,%d,%d,%d,%s,%u,%hu\n", buff_entry->ts,
                    buff_entry->pid, buff_entry->tid, buff_entry->sock_fd,
                    (buff_entry->sock_type == 1) ? "SOCK_STREAM" : "SOCK_DGRAM",
                    ntohl(buff_entry->addr_v4), ntohs(buff_entry->port));
        else
            log_entry_length = sprintf(log_entry, "%lld,%d,%d,%d,%s,%x:%x:%x:%x:%x:%x:%x:%x,%hu\n",
                    buff_entry->ts, buff_entry->pid, buff_entry->tid, buff_entry->sock_fd,
                    (buff_entry->sock_type == 1) ? "SOCK_STREAM" : "SOCK_DGRAM",
                    ntohs(buff_entry->addr_v6[0]), ntohs(buff_entry->addr_v6[1]),
                    ntohs(buff_entry->addr_v6[2]), ntohs(buff_entry->addr_v6[3]),
                    ntohs(buff_entry->addr_v6[4]), ntohs(buff_entry->addr_v6[5]),
                    ntohs(buff_entry->addr_v6[6]), ntohs(buff_entry->addr_v6[7]),
                    ntohs(buff_entry->port));
        copy_to_user(buff + copied_len, log_entry, log_entry_length);
        copied_len += log_entry_length;
        *offset += 1;
    }

    return copied_len;
}

asmlinkage long (*original_connect)(int, struct sockaddr __user *, int);

asmlinkage long instrumented_connect(int fd, struct sockaddr __user *uservaddr, int addrlen) {
    int ret, err;
    struct timeval ts;
    struct sockaddr_in *addr_in;
    struct sockaddr_in6 *addr_in6;
    struct socket *sock;
    char optval;
    int optlen = sizeof(char);
    unsigned long connect_buff_lock_flags;
    t_connect_buff_entry *buff_entry = NULL;

    /* Timestamp is recorded at the time this instrumented syscall is started. */
    do_gettimeofday(&ts);

    /* If invocation to original syscall is not successful, immediately return. */
    if ((ret = original_connect(fd, uservaddr, addrlen)))
        return ret;

    /* Only create a log entry if socket is using internet protocols IPv4 or IPv6. */
    if ((uservaddr->sa_family == AF_INET || uservaddr->sa_family == AF_INET6) &&
            (sock = sockfd_lookup(fd, &err)))
        /* Only create a log entry if socket is of type SOCK_STREAM (TCP) or SOCK_DGRAM (UDP). */
        if (kernel_getsockopt(sock, SOL_SOCKET, SO_TYPE, &optval, &optlen) == 0 &&
                (optval == 1 || optval == 2)) {
            /* Try to get a spot in the buffer to insert a log entry. */
            spin_lock_irqsave(&connect_buff_lock, connect_buff_lock_flags);
            if (connect_buff_count < CONNECT_BUFF_SIZE)
                buff_entry = &connect_buff[connect_buff_count++];
            spin_unlock_irqrestore(&connect_buff_lock, connect_buff_lock_flags);

            if (buff_entry) {
                /* Insert a log entry in the buffer. */
                buff_entry->ts = ts.tv_sec * 1000000LL + ts.tv_usec;
                buff_entry->pid = task_tgid_nr(current);
                buff_entry->tid = task_pid_nr(current);
                buff_entry->sock_fd = fd;
                buff_entry->sock_type = optval;
                buff_entry->addr_family = uservaddr->sa_family;
                if (buff_entry->addr_family == AF_INET) {
                    addr_in = (struct sockaddr_in *) uservaddr;
                    buff_entry->addr_v4 = (addr_in->sin_addr).s_addr;
                    buff_entry->port = addr_in->sin_port;
                }
                else {
                    addr_in6 = (struct sockaddr_in6 *) uservaddr;
                    buff_entry->addr_v6[0] = (addr_in6->sin6_addr).s6_addr16[0];
                    buff_entry->addr_v6[1] = (addr_in6->sin6_addr).s6_addr16[1];
                    buff_entry->addr_v6[2] = (addr_in6->sin6_addr).s6_addr16[2];
                    buff_entry->addr_v6[3] = (addr_in6->sin6_addr).s6_addr16[3];
                    buff_entry->addr_v6[4] = (addr_in6->sin6_addr).s6_addr16[4];
                    buff_entry->addr_v6[5] = (addr_in6->sin6_addr).s6_addr16[5];
                    buff_entry->addr_v6[6] = (addr_in6->sin6_addr).s6_addr16[6];
                    buff_entry->addr_v6[7] = (addr_in6->sin6_addr).s6_addr16[7];
                    buff_entry->port = addr_in6->sin6_port;
                }
            }
        }
    return 0;
}

/***************************************************************************************************
********************************************** SENDTO **********************************************
***************************************************************************************************/

#define SENDTO_BUFF_SIZE 524288
#define MAX_SENDTO_LOG_ENTRY_LEN 256

typedef struct sendto_buff_entry {
    long long ts;               /* Timestamp */
    int pid;                    /* Process ID */
    int tid;                    /* Thread ID */
    int sock_fd;                /* Socket file descriptor */
    char sock_type;             /* Socket type: SOCK_STREAM (1) or SOCK_DGRAM (2) */
    unsigned short addr_family; /* Address family: AF_INET or AF_INET6 */
    unsigned int addr_v4;       /* IPv4 address (in network byte order) */
    unsigned short addr_v6[8];  /* IPv6 address (in network byte order) */
    unsigned short port;        /* Port (in network byte order) */
} t_sendto_buff_entry;
static t_sendto_buff_entry sendto_buff[SENDTO_BUFF_SIZE];
static int sendto_buff_count = 0;
static DEFINE_SPINLOCK(sendto_buff_lock);

int sendto_proc_read(struct file *proc, char __user *buff, unsigned long len, long long *offset) {
    char log_entry[MAX_SENDTO_LOG_ENTRY_LEN];
    int log_entry_length;
    int copied_len = 0;
    t_sendto_buff_entry *buff_entry;

    /* Write CSV header. */
    if (*offset == 0) {
        log_entry_length = sprintf(log_entry, "TS,PID,TID,SOCK_FD,SOCK_TYPE,IP,PORT\n");
        copy_to_user(buff + copied_len, log_entry, log_entry_length);
        copied_len += log_entry_length;
    }

    /* Write CSV rows. */
    while (*offset < sendto_buff_count && copied_len < len - MAX_SENDTO_LOG_ENTRY_LEN) {
        buff_entry = &sendto_buff[*offset];
        if (buff_entry->addr_family == AF_INET)
            log_entry_length = sprintf(log_entry, "%lld,%d,%d,%d,%s,%u,%hu\n", buff_entry->ts,
                    buff_entry->pid, buff_entry->tid, buff_entry->sock_fd,
                    (buff_entry->sock_type == 1) ? "SOCK_STREAM" : "SOCK_DGRAM",
                    ntohl(buff_entry->addr_v4), ntohs(buff_entry->port));
        else
            log_entry_length = sprintf(log_entry, "%lld,%d,%d,%d,%s,%x:%x:%x:%x:%x:%x:%x:%x,%hu\n",
                    buff_entry->ts, buff_entry->pid, buff_entry->tid, buff_entry->sock_fd,
                    (buff_entry->sock_type == 1) ? "SOCK_STREAM" : "SOCK_DGRAM",
                    ntohs(buff_entry->addr_v6[0]), ntohs(buff_entry->addr_v6[1]),
                    ntohs(buff_entry->addr_v6[2]), ntohs(buff_entry->addr_v6[3]),
                    ntohs(buff_entry->addr_v6[4]), ntohs(buff_entry->addr_v6[5]),
                    ntohs(buff_entry->addr_v6[6]), ntohs(buff_entry->addr_v6[7]),
                    ntohs(buff_entry->port));
        copy_to_user(buff + copied_len, log_entry, log_entry_length);
        copied_len += log_entry_length;
        *offset += 1;
    }

    return copied_len;
}

asmlinkage long (*original_sendto)(int, void __user *, unsigned long, unsigned int,
        struct sockaddr __user *, int);

asmlinkage long instrumented_sendto(int fd, void __user *buff, unsigned long len,
        unsigned int flags, struct sockaddr __user *addr, int addr_len) {
    int ret, err;
    struct timeval ts;
    struct sockaddr_in *addr_in;
    struct sockaddr_in6 *addr_in6;
    struct socket *sock;
    struct sockaddr_storage addr_storage;
    int addr_storage_len;
    char optval;
    int optlen = sizeof(char);
    unsigned long sendto_buff_lock_flags;
    t_sendto_buff_entry *buff_entry = NULL;

    /* Timestamp is recorded at the time this instrumented syscall is started. */
    do_gettimeofday(&ts);

    /* If invocation to original syscall is not successful, immediately return. */
    if ((ret = original_sendto(fd, buff, len, flags, addr, addr_len)) == -1)
        return -1;

    /* Only create a log entry if socket is using internet protocols IPv4 or IPv6. */
    if ((sock = sockfd_lookup(fd, &err)) &&
            ((addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) ||
            (!addr &&
            kernel_getpeername(sock, (struct sockaddr *) &addr_storage, &addr_storage_len) == 0 &&
            (addr_storage.ss_family == AF_INET || addr_storage.ss_family == AF_INET6))))
        /* Only create a log entry if socket is of type SOCK_STREAM (TCP) or SOCK_DGRAM (UDP). */
        if (kernel_getsockopt(sock, SOL_SOCKET, SO_TYPE, &optval, &optlen) == 0 &&
                (optval == 1 || optval == 2)) {
            /* Try to get a spot in the buffer to insert a log entry. */
            spin_lock_irqsave(&sendto_buff_lock, sendto_buff_lock_flags);
            if (sendto_buff_count < SENDTO_BUFF_SIZE)
                buff_entry = &sendto_buff[sendto_buff_count++];
            spin_unlock_irqrestore(&sendto_buff_lock, sendto_buff_lock_flags);

            if (buff_entry) {
                /* Insert a log entry in the buffer. */
                buff_entry->ts = ts.tv_sec * 1000000LL + ts.tv_usec;
                buff_entry->pid = task_tgid_nr(current);
                buff_entry->tid = task_pid_nr(current);
                buff_entry->sock_fd = fd;
                buff_entry->sock_type = optval;
                buff_entry->addr_family = (addr) ? addr->sa_family : addr_storage.ss_family;
                if (buff_entry->addr_family == AF_INET) {
                    addr_in = (struct sockaddr_in *) ((addr) ? addr :
                            (struct sockaddr *) &addr_storage);
                    buff_entry->addr_v4 = (addr_in->sin_addr).s_addr;
                    buff_entry->port = addr_in->sin_port;
                }
                else {
                    addr_in6 = (struct sockaddr_in6 *) ((addr) ? addr :
                            (struct sockaddr *) &addr_storage);
                    buff_entry->addr_v6[0] = (addr_in6->sin6_addr).s6_addr16[0];
                    buff_entry->addr_v6[1] = (addr_in6->sin6_addr).s6_addr16[1];
                    buff_entry->addr_v6[2] = (addr_in6->sin6_addr).s6_addr16[2];
                    buff_entry->addr_v6[3] = (addr_in6->sin6_addr).s6_addr16[3];
                    buff_entry->addr_v6[4] = (addr_in6->sin6_addr).s6_addr16[4];
                    buff_entry->addr_v6[5] = (addr_in6->sin6_addr).s6_addr16[5];
                    buff_entry->addr_v6[6] = (addr_in6->sin6_addr).s6_addr16[6];
                    buff_entry->addr_v6[7] = (addr_in6->sin6_addr).s6_addr16[7];
                    buff_entry->port = addr_in6->sin6_port;
                }
            }
        }
    return ret;
}

/***************************************************************************************************
********************************************* RECVFROM *********************************************
***************************************************************************************************/

#define RECVFROM_BUFF_SIZE 524288
#define MAX_RECVFROM_LOG_ENTRY_LEN 256

typedef struct recvfrom_buff_entry {
    long long ts;               /* Timestamp */
    int pid;                    /* Process ID */
    int tid;                    /* Thread ID */
    int sock_fd;                /* Socket file descriptor */
    char sock_type;             /* Socket type: SOCK_STREAM (1) or SOCK_DGRAM (2) */
    unsigned short addr_family; /* Address family: AF_INET or AF_INET6 */
    unsigned int addr_v4;       /* IPv4 address (in network byte order) */
    unsigned short addr_v6[8];  /* IPv6 address (in network byte order) */
    unsigned short port;        /* Port (in network byte order) */
} t_recvfrom_buff_entry;
static t_recvfrom_buff_entry recvfrom_buff[RECVFROM_BUFF_SIZE];
static int recvfrom_buff_count = 0;
static DEFINE_SPINLOCK(recvfrom_buff_lock);

int recvfrom_proc_read(struct file *proc, char __user *buff, unsigned long len, long long *offset) {
    char log_entry[MAX_RECVFROM_LOG_ENTRY_LEN];
    int log_entry_length;
    int copied_len = 0;
    t_recvfrom_buff_entry *buff_entry;

    /* Write CSV header. */
    if (*offset == 0) {
        log_entry_length = sprintf(log_entry, "TS,PID,TID,SOCK_FD,SOCK_TYPE,IP,PORT\n");
        copy_to_user(buff + copied_len, log_entry, log_entry_length);
        copied_len += log_entry_length;
    }

    /* Write CSV rows. */
    while (*offset < recvfrom_buff_count && copied_len < len - MAX_RECVFROM_LOG_ENTRY_LEN) {
        buff_entry = &recvfrom_buff[*offset];
        if (buff_entry->addr_family == AF_INET)
            log_entry_length = sprintf(log_entry, "%lld,%d,%d,%d,%s,%u,%hu\n", buff_entry->ts,
                    buff_entry->pid, buff_entry->tid, buff_entry->sock_fd,
                    (buff_entry->sock_type == 1) ? "SOCK_STREAM" : "SOCK_DGRAM",
                    ntohl(buff_entry->addr_v4),
                    (buff_entry->sock_type == 1) ? ntohs(buff_entry->port) : 0);
        else
            log_entry_length = sprintf(log_entry, "%lld,%d,%d,%d,%s,%x:%x:%x:%x:%x:%x:%x:%x,%hu\n",
                    buff_entry->ts, buff_entry->pid, buff_entry->tid, buff_entry->sock_fd,
                    (buff_entry->sock_type == 1) ? "SOCK_STREAM" : "SOCK_DGRAM",
                    ntohs(buff_entry->addr_v6[0]), ntohs(buff_entry->addr_v6[1]),
                    ntohs(buff_entry->addr_v6[2]), ntohs(buff_entry->addr_v6[3]),
                    ntohs(buff_entry->addr_v6[4]), ntohs(buff_entry->addr_v6[5]),
                    ntohs(buff_entry->addr_v6[6]), ntohs(buff_entry->addr_v6[7]),
                    (buff_entry->sock_type == 1) ? ntohs(buff_entry->port) : 0);
        copy_to_user(buff + copied_len, log_entry, log_entry_length);
        copied_len += log_entry_length;
        *offset += 1;
    }

    return copied_len;
}

asmlinkage long (*original_recvfrom)(int, void __user *, unsigned long, unsigned int,
        struct sockaddr __user *, int __user *);

asmlinkage long instrumented_recvfrom(int fd, void __user *ubuf, unsigned long size,
        unsigned int flags, struct sockaddr __user *addr, int __user *addr_len) {
    int ret, err;
    struct timeval ts;
    struct sockaddr_in *addr_in;
    struct sockaddr_in6 *addr_in6;
    struct socket *sock;
    struct sockaddr_storage addr_storage;
    int addr_storage_len;
    char optval;
    int optlen = sizeof(char);
    unsigned long recvfrom_buff_lock_flags;
    t_recvfrom_buff_entry *buff_entry = NULL;

    /* Timestamp is recorded at the time this instrumented syscall is started. */
    do_gettimeofday(&ts);

    /* If invocation to original syscall is not successful, immediately return. */
    if ((ret = original_recvfrom(fd, ubuf, size, flags, addr, addr_len)) <= 0)
        return ret;

    /* Only create a log entry if socket is using internet protocols IPv4 or IPv6. */
    if ((sock = sockfd_lookup(fd, &err)) &&
            ((addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) ||
            (!addr &&
            kernel_getpeername(sock, (struct sockaddr *) &addr_storage, &addr_storage_len) == 0 &&
            (addr_storage.ss_family == AF_INET || addr_storage.ss_family == AF_INET6))))
        /* Only create a log entry if socket is of type SOCK_STREAM (TCP) or SOCK_DGRAM (UDP). */
        if (kernel_getsockopt(sock, SOL_SOCKET, SO_TYPE, &optval, &optlen) == 0 &&
                (optval == 1 || optval == 2)) {
            /* Try to get a spot in the buffer to insert a log entry. */
            spin_lock_irqsave(&recvfrom_buff_lock, recvfrom_buff_lock_flags);
            if (recvfrom_buff_count < RECVFROM_BUFF_SIZE)
                buff_entry = &recvfrom_buff[recvfrom_buff_count++];
            spin_unlock_irqrestore(&recvfrom_buff_lock, recvfrom_buff_lock_flags);

            if (buff_entry) {
                /* Insert a log entry in the buffer. */
                buff_entry->ts = ts.tv_sec * 1000000LL + ts.tv_usec;
                buff_entry->pid = task_tgid_nr(current);
                buff_entry->tid = task_pid_nr(current);
                buff_entry->sock_fd = fd;
                buff_entry->sock_type = optval;
                buff_entry->addr_family = (addr) ? addr->sa_family : addr_storage.ss_family;
                if (buff_entry->addr_family == AF_INET) {
                    addr_in = (struct sockaddr_in *) ((addr) ? addr :
                            (struct sockaddr *) &addr_storage);
                    buff_entry->addr_v4 = (addr_in->sin_addr).s_addr;
                    if (optval == 1)
                        buff_entry->port = addr_in->sin_port;
                }
                else {
                    addr_in6 = (struct sockaddr_in6 *) ((addr) ? addr :
                            (struct sockaddr *) &addr_storage);
                    buff_entry->addr_v6[0] = (addr_in6->sin6_addr).s6_addr16[0];
                    buff_entry->addr_v6[1] = (addr_in6->sin6_addr).s6_addr16[1];
                    buff_entry->addr_v6[2] = (addr_in6->sin6_addr).s6_addr16[2];
                    buff_entry->addr_v6[3] = (addr_in6->sin6_addr).s6_addr16[3];
                    buff_entry->addr_v6[4] = (addr_in6->sin6_addr).s6_addr16[4];
                    buff_entry->addr_v6[5] = (addr_in6->sin6_addr).s6_addr16[5];
                    buff_entry->addr_v6[6] = (addr_in6->sin6_addr).s6_addr16[6];
                    buff_entry->addr_v6[7] = (addr_in6->sin6_addr).s6_addr16[7];
                    if (optval == 1)
                        buff_entry->port = addr_in6->sin6_port;
                }
            }
        }
    return ret;
}

/**************************************************************************************************
 ********************************************* HIJACK *********************************************
 **************************************************************************************************/

static const struct file_operations connect_proc_ops = {
    .read = (void *) connect_proc_read
};
static struct proc_dir_entry *connect_proc_dir_entry;

static const struct file_operations sendto_proc_ops = {
    .read = (void *) sendto_proc_read
};
static struct proc_dir_entry *sendto_proc_dir_entry;

static const struct file_operations recvfrom_proc_ops = {
    .read = (void *) recvfrom_proc_read
};
static struct proc_dir_entry *recvfrom_proc_dir_entry;

static int __init hijack_tcpip(void) {
    connect_proc_dir_entry = proc_create("milliScope_connect", 0, NULL, &connect_proc_ops);
    original_connect = (void *) sys_call_table[__NR_connect];
    sys_call_table[__NR_connect] = (void *) &instrumented_connect;

    sendto_proc_dir_entry = proc_create("milliScope_sendto", 0, NULL, &sendto_proc_ops);
    original_sendto = (void *) sys_call_table[__NR_sendto];
    sys_call_table[__NR_sendto] = (void *) &instrumented_sendto;

    recvfrom_proc_dir_entry = proc_create("milliScope_recvfrom", 0, NULL, &recvfrom_proc_ops);
    original_recvfrom = (void *) sys_call_table[__NR_recvfrom];
    sys_call_table[__NR_recvfrom] = (void *) &instrumented_recvfrom;

    printk(KERN_INFO "Hijacked the TCP/IP stack.\n");

    return 0;
}

static void __exit restore_tcpip(void) {
    sys_call_table[__NR_connect] = (void *) original_connect;
    proc_remove(connect_proc_dir_entry);

    sys_call_table[__NR_sendto] = (void *) original_sendto;
    proc_remove(sendto_proc_dir_entry);

    sys_call_table[__NR_recvfrom] = (void *) original_recvfrom;
    proc_remove(recvfrom_proc_dir_entry);

    printk(KERN_INFO "Restored the TCP/IP stack.\n");
}

module_init(hijack_tcpip);
module_exit(restore_tcpip);
