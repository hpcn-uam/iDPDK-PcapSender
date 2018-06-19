#!/bin/bash

#Base parameters
TXQUEUES=1
NICIFACE=0
BASECPU=2

if [ $# -le 0 ]
    then echo "A pcap file should be provided to this script. Example: ./scripts/scriptname.sh file.pcap [num of queues]"
    exit 1
fi

if [ $# -gt 1 ]
    then TXQUEUES=$2
fi

TXPARAM="($NICIFACE,0,$BASECPU)"
if [ $TXQUEUES -gt 1 ]; then
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
        build/app/hpcn_pcapreplay -c FF -n 6 -- --rx "($NICIFACE,0,$BASECPU)" --tx "$TXPARAM" \
                --rsz "1024, 1024" \
                --bsz "144, 144" \
		--pcap "$1"
