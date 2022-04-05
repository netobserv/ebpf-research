#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>

extern char *optarg;

struct pseudo_header //needed for checksum calculation
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short length;

    struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr, int n)
{
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (n > 1)
    {
        sum += *ptr++;
        n -= 2;
    }

    if (n == 1)
    {
        oddbyte = 0;
        *((char *)&oddbyte) = *(char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

unsigned long npackets = 0;
void timer_handler(int signum)
{
    //printf("%d packets sent\n", npackets);
    exit(0);
}

void usage()
{
    printf("usage: yapktgen -s <source ip> -d <dest ip> -p <payload size> -d <duration in sec>\n");
    exit(1);
}

char datagram[65536], sip[16], dip[16];
struct iphdr *iph = (struct iphdr *)datagram;
struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
struct sockaddr_in sin;
struct pseudo_header psh;
int opt, sock, payload = 1024, duration = 10;
struct itimerval timer;

void initPacket() {
    if (sip == NULL || dip == NULL)
    {
        usage();
    }

    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    memset(datagram, 0, 65536);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr) + payload;
    iph->id = htons(54321);
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(sip);
    iph->daddr = inet_addr(dip);
    iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);

    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);

    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(20);

    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

    int value = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value)) < 0)
    {
        fprintf(stderr, "Error %s\n", strerror(errno));
        exit(1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;
    unsigned long ports = 1;
    int port1 = ports & 0xffff;
    int port2 = (ports >> 16) & 0xffff;

    tcph->source = htons(port1 > 0 ? port1 : 1);
    tcph->dest = htons(port2 > 0 ? port2 : 1);
    tcph->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

    sin.sin_port = tcph->dest;

    /* Install timer_handler as the signal handler for SIGVTALRM. */
    if (signal(SIGALRM, timer_handler) == SIG_ERR)
    {
        fprintf(stderr, "Error %s\n", strerror(errno));
        exit(1);
    }

    timer.it_value.tv_sec = duration;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;

    printf("Start injection for :%d sec\n", duration);

    setitimer(ITIMER_REAL, &timer, NULL);

}

long cexec (char* command) {
   char buffer[64];
   char result[30] = "";
   char *val;
   long tx;
   // Open pipe to file
   FILE* pipe = popen(command, "r");
   if (!pipe) {
      return 0;
   }

   // read till end of process:
   while (!feof(pipe)) {
      // use buffer to read and add to result
      if (fgets(buffer, 64, pipe) != NULL)
         //result += buffer;
         strcat(result, buffer);
   }

   pclose(pipe);
   tx = strtol(result, &val, 10);
   return tx;
}

void* monitorPps (void* args) {
	long txPkts;
	long newtxPkts;
	long aggtxPkts = 0;
	long intervalPkts;
	float aggPps = 0.0;
	float avgPps;
	char mycommand[] = "sudo cat /sys/class/net/ens6f0np0/statistics/tx_packets";
	txPkts = cexec(mycommand);

	printf("starting with txpkts = %lu\n", txPkts);
	int round=0;
	sleep(1);
	while (1) {
		newtxPkts = cexec(mycommand);
		intervalPkts = newtxPkts - txPkts;
		float rate = (float)(intervalPkts)/(float)1000000;
		aggPps +=rate;
		aggtxPkts+=intervalPkts;
		printf("Tx traffic at %f Mpps, total pkts sent =%lu\n", rate, aggtxPkts);
		txPkts = newtxPkts;
		sleep(1);
		round++;
		if (aggtxPkts > 100000000) {
			printf("Total pkts sent =%lu\n", aggtxPkts);
			avgPps = aggPps/(float)round;
			printf("Avg PPS = %f Mpps\n", avgPps);
			exit(1);
		}
	}
}

void *sendPacket(void* args) {
    while (1)
    {

        if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            fprintf(stderr, "Error %s\n", strerror(errno));
            exit(1);
        }
        //npackets++;
    }

}
int main(int argc, char **argv)
{
    pthread_t monitor_thread;
    int num_threads = 40;
    pthread_t packet_thread[100];
    while ((opt = getopt(argc, argv, "s:d:p:t:")) != -1)
    {
        switch (opt)
        {
        case 's':
            strcpy(sip, optarg);
            break;
        case 'd':
            strcpy(dip, optarg);
            break;
        case 'p':
            payload = atoi(optarg);
            break;
        case 't':
            duration = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Unknow option !");
            usage();
        }
    }

    initPacket();
    printf("Before Thread\n");
    pthread_create(&monitor_thread, NULL, monitorPps, NULL);
    for (int i=0;i<num_threads;i++) {
        pthread_create(&packet_thread[i], NULL, sendPacket, NULL);
    }

    pthread_join(monitor_thread, NULL);

    return 0;
}
