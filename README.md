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
/*
 * kconnect_trace.bt
 *
 * Traces outbound TCP (v4/v6) connects and UDP sends and emits one
 * pipe-delimited line per event on stdout, in the exact format expected
 * by the KConnect Core C display program:
 *
 *      pid|comm|proto|daddr|dport|sport
 *
 * Usage:
 *      sudo bpftrace -q kconnect_trace.bt | ./kconnect_core
 *
 * The -q flag suppresses bpftrace's normal "Attaching N probes..." banner
 * so only clean data lines hit the pipe.
 *
 * Note: AF_INET / AF_INET6 are not builtin identifiers on every bpftrace
 * version, so we use the raw numeric family values instead:
 *   2  = AF_INET
 *   10 = AF_INET6
 * ntop() infers v4 vs v6 from the byte width of the value passed in, so
 * no explicit family argument is needed there.
 */

/* ---------------- TCP IPv4 ---------------- */

kprobe:tcp_v4_connect
{
    // arg0 of tcp_v4_connect(struct sock *sk, ...) is the sock pointer.
    // Stash it per-thread so the kretprobe can recover it on return.
    @sock4[tid] = arg0;
}

kretprobe:tcp_v4_connect
/@sock4[tid] && retval == 0/
{
    $sk    = (struct sock *)@sock4[tid];
    $daddr = ntop($sk->__sk_common.skc_daddr);
    $dport = $sk->__sk_common.skc_dport;
    $dport = ($dport >> 8) | (($dport << 8) & 0xff00);   // network -> host byte order
    $sport = $sk->__sk_common.skc_num;

    printf("%d|%s|%s|%s|%d|%d\n", pid, comm, "TCP", $daddr, $dport, $sport);
}

kretprobe:tcp_v4_connect
{
    delete(@sock4[tid]);
}

/* ---------------- TCP IPv6 ---------------- */

kprobe:tcp_v6_connect
{
    @sock6[tid] = arg0;
}

kretprobe:tcp_v6_connect
/@sock6[tid] && retval == 0/
{
    $sk    = (struct sock *)@sock6[tid];
    $daddr = ntop($sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    $dport = $sk->__sk_common.skc_dport;
    $dport = ($dport >> 8) | (($dport << 8) & 0xff00);
    $sport = $sk->__sk_common.skc_num;

    printf("%d|%s|%s|%s|%d|%d\n", pid, comm, "TCP", $daddr, $dport, $sport);
}

kretprobe:tcp_v6_connect
{
    delete(@sock6[tid]);
}

/* ---------------- UDP (v4) ---------------- */

kprobe:udp_sendmsg
{
    $sk = (struct sock *)arg0;

    if ($sk->__sk_common.skc_family == 2) {          // AF_INET
        $raw_daddr = $sk->__sk_common.skc_daddr;
        $dport     = $sk->__sk_common.skc_dport;
        $dport     = ($dport >> 8) | (($dport << 8) & 0xff00);
        $sport     = $sk->__sk_common.skc_num;

        // skc_daddr/skc_dport are only populated for "connected" UDP
        // sockets; skip unconnected sendto()s with no fixed destination
        // (raw daddr of 0 means unset).
        if ($dport > 0 && $raw_daddr != 0) {
            $daddr = ntop($raw_daddr);
            printf("%d|%s|%s|%s|%d|%d\n", pid, comm, "UDP", $daddr, $dport, $sport);
        }
    }
}

/* ---------------- cleanup ---------------- */

END
{
    clear(@sock4);
    clear(@sock6);
}






## New CODE

#!/usr/bin/env bpftrace

tracepoint:sock:inet_sock_set_state
{
    // 1 corresponds to TCP_ESTABLISHED, using the correct kernel field: newstate
    if (args->newstate == 1) {
        $daddr = ntop(args->family, args->daddr);

        // Output format matched precisely to your C parser: pid|comm|proto|daddr|dport|sport
        printf("%d|%s|TCP|%s|%d|%d\n",
            pid,
            comm,
            $daddr,
            args->dport,
            args->sport
        );
    }
}
