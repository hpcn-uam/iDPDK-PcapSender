High Speed Pcap-sender using Intel DPDK
=================

Intel Data Plane Development Kit (DPDK) Pcap-Sender

This program allows to send PCAPS preloaded in memory (much biggers than pktgen does ;)).


Compilation
=================
The program can be easly compiled using the makefile provided.
It needs (as anyother DPDK app) the DPDK env. variables such as *RTE_SDK* to be defined first.

The script *setup.sh* can be used to compile everything. Feel free to modify the script and modify those variables.


Execution
=================
The script provided can send a PCAP throught only one interface. Future improvements will allow to send to more ports
