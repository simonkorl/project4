#!/bin/bash
# cd ./ 
# python3 traffic_control.py -load trace/traces.txt > tc.log 2>&1 &
# rm client.log > tmp.log 2>&1
# sleep 0.2
#./server serverIP serverPort   [ipv6Address%networkInterface]:8888   任意串1   任意串2  blockconf位置（中间三个参数用于与课题四交互,需要与client相同
LD_LIBRARY_PATH=./lib RUST_LOG=debug ./client 127.0.0.1 5555 [fd04::2%enp5s0]:8888 fd02::5 fd02::5 --no-verify 
#python3 traffic_control.py --reset ens33
    
