High Speed Pcap-sender using Intel DPDK
=================

Intel Data Plane Development Kit (DPDK) Pcap-Sender

This program allows to send PCAPS preloaded in memory (much biggers than other tools)).


Compilation
=================
The program can be easly compiled using the makefile provided.
It needs (as anyother DPDK app) the DPDK enviromental variables such as *RTE_SDK* to be defined first.

Execution
=================
- The script `interface0.sh` send a PCAP throught a the interface 0.
- The script `interface0.caida.sh` send a caida's PCAP throught a the interface 0.

If other interfaces should be used, feel free to edit those scripts or execute directly the compiled application at `./src/build/app/hpcn_pcapreplay`. Extended instrunctions with parameter `-h`.
