# KConnect-Core
## IET Systems SMP Final Boss
### Deadline is 7th July
* Kudos to all of you for making it so far.
* But now is the time for the final project implementation.
* The kernel side eBPF C code has been given, go through it and write the corresponding bpftrace script. 
* Your output should look something like this:
 ![output](./final_output.png)
* Fork this repo, and start getting your hands dirty.
#### Execution Instructions:
* Compile the display program: `gcc -o kconnectcore kconnectcore.c`
* Run the pipeline: `sudo bpftrace kconnectcore.bt | ./kconnectcore`

  
#### Best of Luck !!!!



#!/usr/bin/env bpftrace

#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

BEGIN
{
    printf("# PID|COMM|PROTO|DEST_IP|DEST_PORT|SRC_PORT\n");
}

/* TCP IPv4 connections */
kprobe:tcp_v4_connect
{
    $sk = (struct sock *)arg0;

    printf("%d|%s|TCP|%s|%d|%d\n",
        pid,
        comm,
        ntop(AF_INET, $sk->__sk_common.skc_daddr),
        ntohs($sk->__sk_common.skc_dport),
        ntohs($sk->__sk_common.skc_num));
}

/* UDP IPv4 send */
kprobe:udp_sendmsg
{
    $sk = (struct sock *)arg0;

    printf("%d|%s|UDP|%s|%d|%d\n",
        pid,
        comm,
        ntop(AF_INET, $sk->__sk_common.skc_daddr),
        ntohs($sk->__sk_common.skc_dport),
        ntohs($sk->__sk_common.skc_num));
}

/* TCP IPv6 */
kprobe:tcp_v6_connect
{
    $sk = (struct sock *)arg0;

    printf("%d|%s|TCP|%s|%d|%d\n",
        pid,
        comm,
        ntop(AF_INET6, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8),
        ntohs($sk->__sk_common.skc_dport),
        ntohs($sk->__sk_common.skc_num));
}
