#!/bin/bash

#Base parameters
TXQUEUES=1
NICIFACE=0
BASECPU=2

if [ $# -le 0 ]
    then echo "A pcap file should be provided to this script. Example: ./scripts/scriptname.sh file.pcap [num of queues]"
    exit 1
fi

if [ $# -eq 3 ]
    then TXQUEUES=$2
    exit 1
fi

TXPARAM="($NICIFACE,0,$BASECPU)"
if [ $TXQUEUES -gt 1 ]; then
        TXQUEUES=$(($TXQUEUES + 1))
        for i in $(seq 2 $TXQUEUES); do
                QUEUE=$(($i - 1))
                CCPU=$(($BASECPU + $QUEUE))
                TXPARAM="$TXPARAM,($NICIFACE,$QUEUE,$CCPU)"
        done
fi

if [ -z ${RTE_SDK+x} ]; then
        export RTE_SDK=$(pwd)/dpdk
fi

git submodule update --init # updates dependencies
cd src
make && \
        build/app/hpcn_pcapreplay -c F -n 2 -- --rx "(0,0,1)" --tx "$TXPARAM" \
                --rsz "1024, 1024" \
                --bsz "144, 144" \
		--pcap "$1"