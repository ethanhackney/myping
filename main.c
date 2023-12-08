#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sysexits.h>
#include <unistd.h>

enum {
        BUFSIZE = 1500,
};

static void sig_alrm(int signo);

static struct sockaddr  *g_sendaddr;
static socklen_t        g_salen;
static pid_t            g_pid;
static char             *g_host;
static int              g_nr_sent;
static int              g_sockfd;

int
main(int argc, char **argv)
{
        struct sigaction        act;
        struct addrinfo         hints;
        struct addrinfo         *ai;
        struct msghdr           msg;
        struct iovec            iov;
        struct icmp             *icmp;
        struct ip               *ip;
        ssize_t                 n;
        char                    recvbuf[BUFSIZE];
        char                    ctlbuf[BUFSIZE];
        int                     icmplen;
        int                     hlen;
        int                     error;

        if (argc != 2)
                errx(EX_USAGE, "ping host");
        g_host = argv[1];

        g_pid = getpid() & 0xffff;

        memset(&act, 0, sizeof(act));
        act.sa_flags = 0;
        act.sa_handler = sig_alrm;
        sigemptyset(&act.sa_mask);
        if (sigaction(SIGALRM, &act, NULL) < 0)
                err(EX_OSERR, "sigaction()");

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_CANONNAME;
        hints.ai_family = AF_INET;
        error = getaddrinfo(g_host, NULL, &hints, &ai);
        if (error != 0)
                errx(EX_SOFTWARE, "getaddrinfo(): %s", gai_strerror(error));

        g_sendaddr = ai->ai_addr;
        g_salen = ai->ai_addrlen;

        g_sockfd = socket(ai->ai_family, SOCK_RAW, IPPROTO_ICMP);
        if (g_sockfd < 0)
                err(EX_OSERR, "socket()");

        sig_alrm(SIGALRM);

        iov.iov_base = recvbuf;
        iov.iov_len = sizeof(recvbuf);
        msg.msg_name = g_sendaddr;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctlbuf;
        for (;;) {
                msg.msg_namelen = g_salen;
                msg.msg_controllen = sizeof(ctlbuf);
                n = recvmsg(g_sockfd, &msg, 0);
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0)
                        err(EX_OSERR, "recvmsg()");

                ip = (struct ip *)recvbuf;
                hlen = ip->ip_hl << 2;
                if (ip->ip_p != IPPROTO_ICMP)
                        continue;

                icmp = (struct icmp *)(recvbuf + hlen);
                icmplen = n - hlen;
                if (icmplen < 8)
                        continue;

                if (icmp->icmp_type != ICMP_ECHOREPLY)
                        continue;
                if (icmp->icmp_id != g_pid)
                        continue;
                if (icmplen < 16)
                        continue;

                printf("%d bytes from %s: seq=%u, ttl=%d\n",
                       icmplen,
                       g_host,
                       icmp->icmp_seq,
                       ip->ip_ttl);
        }
}

static void
sig_alrm(int signo)
{
        struct icmp     *icmp;
        uint32_t        cksum;
        uint16_t        *ckptr;
        uint16_t        answer;
        char            sendbuf[BUFSIZE];
        int             len;
        int             nleft;

        icmp = (struct icmp *)sendbuf;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = g_pid;
        icmp->icmp_seq = g_nr_sent++;
        memset(icmp->icmp_data, 0xa5, 56);

        if (gettimeofday((struct timeval *)icmp->icmp_data, NULL) < 0)
                err(EX_OSERR, "gettimeofday()");

        len = 8 + 56;

        nleft = len;
        cksum = 0;
        answer = 0;
        ckptr = (uint16_t *)icmp;
        while (nleft > 1) {
                cksum += *ckptr++;
                nleft -= 2;
        }
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)ckptr;
                cksum += answer;
        }
        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >> 16);
        answer = ~cksum;
        icmp->icmp_cksum = answer;

        if (sendto(g_sockfd, sendbuf, len, 0, g_sendaddr, g_salen) < 0)
                err(EX_OSERR, "sendto()");

        alarm(1);
}
