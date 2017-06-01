#!/bin/bash

if [ $# -ne 1 ]
    then echo "A pcap file should be provided to this script. Example: ./scripts/scriptname.sh file.pcap"
    exit 1
fi

git submodule update --init
cd src
make

        # c = numero de procesadores
        # n = numero de canales de memoria
        # --rx "(PORT, QUEUE, LCORE), ..." : List of NIC RX ports and queues
        # tx "(PORT, LCORE), ..." : List of NIC TX ports handled by the I/O TX
        # w "LCORE, ..." : List of the worker lcores
        # OPTIONAL:
        # rsz "A, B, C, D" : Ring sizes
        #   A = Size (in number of buffer descriptors) of each of the NIC RX
        #       rings read by the I/O RX lcores (default value is 1024)
        #   B = Size (in number of elements) of each of the SW rings used by the
        #       I/O RX lcores to send packets to worker lcores (default value is
        #       1024)
        #   C = Size (in number of elements) of each of the SW rings used by the
        #       worker lcores to send packets to I/O TX lcores (default value is
        #       1024)
        #   D = Size (in number of buffer descriptors) of each of the NIC TX
        #       rings written by I/O TX lcores (default value is 1024)
        # bsz "(A, B), (C, D), (E, F)" :  Burst sizes
        #   A = I/O RX lcore read burst size from NIC RX (default value is 144)
        #   B = I/O RX lcore write burst size to output SW rings (default value
        #       is 144)
        #   C = Worker lcore read burst size from input SW rings (default value
        #       is 144)
        #   D = Worker lcore write burst size to output SW rings (default value
        #       is 144)
        #   E = I/O TX lcore read burst size from input SW rings (default value
        #       is 144)
        #   F = I/O TX lcore write burst size to NIC TX (default value is 144)

        build/app/hpcn_n2d -c F -n 2 -- --rx "(0,0,1)" --tx "(0,2)" \
                --rsz "1024, 2048, 1024, 1024" \
                --bsz "(144, 144), (144, 144), (144, 144)" \
		--caida --pcap "$1"