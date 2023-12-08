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

/* sends an ICMP packet every one second */
static void sig_alrm(int signo);
/* calculate checksum */
static uint16_t icmp_cksum(uint16_t *pkt, int len);

/* address we are sending to */
static struct sockaddr  *g_sendaddr;
/* length of address */
static socklen_t        g_salen;
/* our PID */
static pid_t            g_pid;
/* hostname of who we are sending to */
static char             *g_host;
/* number of packets sent so far */
static int              g_nr_sent;
/* raw socket descriptor */
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

        /* get host argument */
        if (argc != 2)
                errx(EX_USAGE, "ping host");
        g_host = argv[1];

        /* save our pid for ICMP id field */
        g_pid = getpid() & 0xffff;

        /* setup SIGALRM handler */
        memset(&act, 0, sizeof(act));
        act.sa_flags = 0;
        act.sa_handler = sig_alrm;
        sigemptyset(&act.sa_mask);
        if (sigaction(SIGALRM, &act, NULL) < 0)
                err(EX_OSERR, "sigaction()");

        /* get addrinfo for host */
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_CANONNAME;
        hints.ai_family = AF_INET;
        error = getaddrinfo(g_host, NULL, &hints, &ai);
        if (error != 0)
                errx(EX_SOFTWARE, "getaddrinfo(): %s", gai_strerror(error));
        g_sendaddr = ai->ai_addr;
        g_salen = ai->ai_addrlen;

        /* open up raw socket */
        g_sockfd = socket(ai->ai_family, SOCK_RAW, IPPROTO_ICMP);
        if (g_sockfd < 0)
                err(EX_OSERR, "socket()");

        /* send first packet */
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

                /* did we get interrupted by SIGALRM? */
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0)
                        err(EX_OSERR, "recvmsg()");

                /* make sure we have an ICMP packet */
                ip = (struct ip *)recvbuf;
                hlen = ip->ip_hl << 2;
                if (ip->ip_p != IPPROTO_ICMP)
                        continue;

                /* make sure it is not malformed */
                icmp = (struct icmp *)(recvbuf + hlen);
                icmplen = n - hlen;
                if (icmplen < 8)
                        continue;

                /* make sure its an ECHOREPLY */
                if (icmp->icmp_type != ICMP_ECHOREPLY)
                        continue;
                /* make sure its for us */
                if (icmp->icmp_id != g_pid)
                        continue;
                /* make sure its the right size */
                if (icmplen < 16)
                        continue;

                /* print results of ping */
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
        char            sendbuf[BUFSIZE];
        int             len;

        /* setup ICMP header */
        icmp = (struct icmp *)sendbuf;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = g_pid;
        icmp->icmp_seq = g_nr_sent++;
        memset(icmp->icmp_data, 0xa5, 56);
        if (gettimeofday((struct timeval *)icmp->icmp_data, NULL) < 0)
                err(EX_OSERR, "gettimeofday()");

        /* compute checksum */
        len = 8 + 56;
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = icmp_cksum((uint16_t *)icmp, len);

        /* send it */
        if (sendto(g_sockfd, sendbuf, len, 0, g_sendaddr, g_salen) < 0)
                err(EX_OSERR, "sendto()");

        /* setup another alarm one second from now */
        alarm(1);
}

/* calculate checksum */
static uint16_t
icmp_cksum(uint16_t *pkt, int len)
{
        uint32_t        sum = 0;
        uint16_t        *w = pkt;
        uint16_t        answer = 0;
        int             nleft = len;

        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w;
                sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;
}
