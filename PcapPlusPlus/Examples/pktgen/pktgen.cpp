/**
 * Packet Generator
 */

#include <stdlib.h>
#include <iostream>
#include <fstream>
#ifndef _MSC_VER
#include "unistd.h"
#endif
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include "SystemUtils.h"
#include <thread>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <getopt.h>


#define SEND_TIMEOUT_BEFORE_FT_START 3

#define SLEEP_BETWEEN_ABORT_MESSAGES  100000 // 100 msec
#define NUM_OF_ABORT_MESSAGES_TO_SEND 5

#define MAX_PACKETS 1000000000 // 1B


void printUsage()
{
	std::string thisSideInterface = "interface";
	std::string otherSideIP = "ip";

	std::cout << std::endl
		<< "Usage:" << std::endl
		<< "------" << std::endl
		<< pcpp::AppName::get() << " [-h] [-v] [-l] -i " << thisSideInterface << " -d " << otherSideIP
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -i " << thisSideInterface << " : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address" << std::endl
		<< "    -d " << otherSideIP << "       :" << " IPv4 address" << std::endl
		<< "    -n " << "threads"   << "       : Number of threads" << std::endl
		<< std::endl;
}



#define EXIT_WITH_ERROR_PRINT_USAGE(reason) do { \
	printUsage(); \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

#define EXIT_WITH_ERROR(reason) do { \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
		exit(1); \
		} while(0)

#define EXIT_WITH_ERROR_AND_RUN_COMMAND(reason, command) do { \
		command; \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
		exit(1); \
		} while(0)



/**
 * Send a file to the catcher
 */
pcpp::IPv4Address senderIP("10.10.10.2");
pcpp::IPv4Address catcherIP("10.10.10.1");
pcpp::MacAddress senderMacAddr;
pcpp::MacAddress catcherMacAddr;
int packetsPerSec = 0;
size_t packetSize = 64;
pcpp::PcapLiveDevice* dev;
int err;

static struct option IcmpFTOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"dest-ip",  required_argument, 0, 'd'},
	{"num-threads", optional_argument, 0, 'n'}
};

void initPacket () {
	// identify the interface to listen and send packets to
	dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(senderIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find network interface with IP '" << senderIP << "'");

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface ");

	// get the MAC address of the interface
	senderMacAddr = dev->getMacAddress();
	if (senderMacAddr == pcpp::MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	// discover the MAC address of the catcher by sending an ARP ping to it
	double arpResTO = 0;
	catcherMacAddr = pcpp::NetworkUtils::getInstance().getMacAddress(catcherIP, dev, arpResTO, senderMacAddr, senderIP, 10);
	if (catcherMacAddr == pcpp::MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find catcher MAC address");

}

long cexec (std::string command) {
   char buffer[64];
   std::string result = "";
	 long tx;
   // Open pipe to file
   FILE* pipe = popen(command.c_str(), "r");
   if (!pipe) {
      return 0;
   }

   // read till end of process:
   while (!feof(pipe)) {
      // use buffer to read and add to result
      if (fgets(buffer, 64, pipe) != NULL)
         result += buffer;
   }

   pclose(pipe);
	 tx = std::stol(result);
   return tx;
}

void monitorPps () {
	long txPkts;
	long newtxPkts;
	long aggtxPkts = 0;
	long intervalPkts;
	float aggPps = 0.0;
	float avgPps;
	std::string mycommand = "sudo cat /sys/class/net/ens6f0np0/statistics/tx_packets";
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

bool sendIcmpMessages() {
	static uint16_t ipID = 0x1234;

	//printf("Starting to send packets\n");
	pcpp::Packet packet;

	// create the different layers

	// Eth first
	pcpp::EthLayer ethLayer(senderMacAddr, catcherMacAddr, PCPP_ETHERTYPE_IP);

	// then IPv4 (IPv6 is not supported)
	pcpp::IPv4Layer ipLayer(senderIP, catcherIP);
	ipLayer.getIPv4Header()->timeToLive = 128;
	// set and increment the IP ID
	ipLayer.getIPv4Header()->ipId = pcpp::hostToNet16(ipID++);

	// then ICMP
	pcpp::IcmpLayer icmpLayer;

	// create an new packet and add all layers to it
	packet.addLayer(&ethLayer);
	packet.addLayer(&ipLayer);
	packet.addLayer(&icmpLayer);
	packet.computeCalculateFields();
	pcpp::RawPacket* rawPacket = packet.getRawPacket();
	const uint8_t *rawData = rawPacket->getRawData();
	int packlen = rawPacket->getRawDataLen();
	while (1) {
		// send the packet through the device
		err = dev->sendPacket(rawData, packlen, false);
		//printf("%d\n", err);
	}
}

bool sendUdpMessages() {
	static uint16_t ipID = 0x1234;

	//printf("Starting to send packets\n");
	pcpp::Packet packet;

	// create the different layers

	// Eth first
	pcpp::EthLayer ethLayer(senderMacAddr, catcherMacAddr, PCPP_ETHERTYPE_IP);

	// then IPv4 (IPv6 is not supported)
	pcpp::IPv4Layer ipLayer(senderIP, catcherIP);
	ipLayer.getIPv4Header()->timeToLive = 128;
	// set and increment the IP ID
	ipLayer.getIPv4Header()->ipId = pcpp::hostToNet16(ipID);

	// then UDP
	pcpp::UdpLayer newUdpLayer(12345, 53);
	// create a new DNS layer
	pcpp::DnsLayer newDnsLayer;
	newDnsLayer.addQuery("www.redhat.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);

	// create an new packet and add all layers to it
	packet.addLayer(&ethLayer);
	packet.addLayer(&ipLayer);
	packet.addLayer(&newUdpLayer);
	packet.addLayer(&newDnsLayer);

	packet.computeCalculateFields();
	pcpp::RawPacket* rawPacket = packet.getRawPacket();
	const uint8_t *rawData = rawPacket->getRawData();
	int packlen = rawPacket->getRawDataLen();
	while (1) {
		// send the packet through the device
		err = dev->sendPacket(rawData, packlen, false);
		//printf("%d\n", err);
	}
}


void readCommandLineArguments(int argc, char* argv[],
		pcpp::IPv4Address& myIP, pcpp::IPv4Address& otherSideIP, int& numThreads)
{
	std::string interfaceNameOrIP;
	std::string otherSideIPAsString;


	int optionIndex = 0;
	int opt = 0;
	while((opt = getopt_long(argc, argv, "i:d:n:", IcmpFTOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'd':
				otherSideIPAsString = optarg;
				break;
			case 'n':
				numThreads = atoi(optarg);
				break;
			default:
				printUsage();
				exit(-1);
		}
	}
	// extract my IP address by interface name or IP address string
	if (interfaceNameOrIP.empty())
		EXIT_WITH_ERROR_PRINT_USAGE("Please provide interface name or IP");

	pcpp::IPv4Address interfaceIP(interfaceNameOrIP);
	if (!interfaceIP.isValid())
	{
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
		if (dev == NULL)
			EXIT_WITH_ERROR_PRINT_USAGE("Cannot find interface by provided name");

		myIP = dev->getIPv4Address();
	}
	else
		myIP = interfaceIP;

	// validate pitcher/catcher IP address
	if (otherSideIPAsString.empty())
		EXIT_WITH_ERROR_PRINT_USAGE("Please provide IP address");

	pcpp::IPv4Address tempIP = pcpp::IPv4Address(otherSideIPAsString);
	if (!tempIP.isValid())
		EXIT_WITH_ERROR_PRINT_USAGE("Invalid IP address");
	otherSideIP = tempIP;
}

/**
 * main method of PacketGen
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);
	int numThreads = 40;

	// disable stdout buffering so all std::cout command will be printed immediately
	setbuf(stdout, NULL);


	// read and parse command line arguments. This method also takes care of arguments correctness. If they're not correct, it'll exit the program
	readCommandLineArguments(argc, argv, senderIP, catcherIP, numThreads);
	initPacket();

	std::vector<std::thread> threads;
	for (int i = 0; i < numThreads; ++i) {
		// cpu_set_t cpuset;
		// CPU_ZERO(&cpuset);
		// CPU_SET(i+1, &cpuset);
		//threads[i](sendMessages);
		threads.push_back(std::thread(sendUdpMessages));
		//int rc = pthread_setaffinity_np(threads[i].native_handle(),
		//									sizeof(cpu_set_t), &cpuset);
	}

	printf("Total Threads = %ld\n", threads.size());

	std::thread monitor(monitorPps);

	monitor.join();
	dev->close();

}
