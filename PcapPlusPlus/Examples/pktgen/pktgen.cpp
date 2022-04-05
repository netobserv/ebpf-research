/**
 * ICMP file transfer utility - pitcher
 * ========================================
 * This utility demonstrates how to transfer files between 2 machines using only ICMP messages.
 * This is the pitcher part of the utility
 * For more information please refer to README.md
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
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include "Common.h"
#include "SystemUtils.h"
#include <thread>
#include <stdexcept>
#include <stdio.h>
#include <string>


#define SEND_TIMEOUT_BEFORE_FT_START 3

#define SLEEP_BETWEEN_ABORT_MESSAGES  100000 // 100 msec
#define NUM_OF_ABORT_MESSAGES_TO_SEND 5

#define MAX_PACKETS 1000000000 // 1B
#ifdef _MSC_VER
#include <windows.h>

void usleep(__int64 usec)
{
	HANDLE timer;
	LARGE_INTEGER ft;

	ft.QuadPart = -(10 * usec); // Convert to 100 nanosecond interval, negative value indicates relative time

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
}
#endif

/**
 * A struct used for start sending a file to the catcher
 */
struct IcmpFileTransferStartSend
{
	uint16_t icmpMsgId;
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
};

/**
 * A struct used for start receiving a file from the catcher
 */
struct IcmpFileTransferStartRecv
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	bool gotFileTransferStartMsg;
	std::string fileName;
};

/**
 * A struct used for receiving file content from the catcher
 */
struct IcmpFileContentData
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	std::ofstream* file;
	uint16_t expectedIcmpId;
	uint32_t fileSize;
	uint32_t MBReceived;
	bool fileTransferCompleted;
	bool fileTransferError;
};



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

bool sendMessages() {
	static uint16_t ipID = 0x1234;

	printf("Starting to send packets\n");
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

/**
 * main method of this ICMP pitcher
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);
	constexpr unsigned num_threads = 30;

	pcpp::IPv4Address senderIP("10.10.10.2");
	pcpp::IPv4Address receiverIP("10.10.10.1");
	int packetsPerSec = 0;
	size_t packetSize = 64;

	// disable stdout buffering so all std::cout command will be printed immediately
	setbuf(stdout, NULL);


	// read and parse command line arguments. This method also takes care of arguments correctness. If they're not correct, it'll exit the program
	//readCommandLineArguments(argc, argv, "pitcher", "catcher", sender, receiver, pitcherIP, catcherIP, fileNameToSend, packetsPerSec, blockSize);
	initPacket();

	std::vector<std::thread> threads;
	for (unsigned i = 0; i < num_threads; ++i) {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(i+1, &cpuset);
		//threads[i](sendMessages);
		threads.push_back(std::thread(sendMessages));
		//int rc = pthread_setaffinity_np(threads[i].native_handle(),
		//									sizeof(cpu_set_t), &cpuset);
	}

	printf("Total Threads = %d\n", threads.size());
	//
	// std::thread th1(sendMessages);
	//
	// std::thread th2(sendMessages);
	// std::thread th3(sendMessages);
	// std::thread th4(sendMessages);
	// std::thread th5(sendMessages);
	// std::thread th6(sendMessages);
	// std::thread th7(sendMessages);
	// std::thread th8(sendMessages);
	// std::thread th9(sendMessages);
	// std::thread th10(sendMessages);
	//sendPackets(senderIP, receiverIP, packetSize, packetsPerSec);
	// send a file to the catcher
	// if (sender)
	// 	sendFile(fileNameToSend, pitcherIP, catcherIP, blockSize, packetsPerSec);
	// // receive a file from the catcher
	// else if (receiver)
	// 	receiveFile(pitcherIP, catcherIP, packetsPerSec);
	std::thread monitor(monitorPps);
	// th1.join();
	// th2.join();
	// th3.join();
	// th4.join();
	// th5.join();
	// th6.join();
	// th7.join();
	// th8.join();
	// th9.join();
	// th10.join();
	monitor.join();
	dev->close();

}
