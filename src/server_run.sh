
    #!/bin/bash
    cd ./ 
    python3 traffic_control.py -aft 3.1 -load trace/traces.txt > tc.log 2>&1 &

    cd ./demo 
    g++ -shared -fPIC solution.cxx -I. -o libsolution.so > compile.log 2>&1
    cp libsolution.so ../lib

    # check port
    a=`lsof -i:5555 | awk '/server/ {print$2}'`
    if [ $a > 0 ]; then
        kill -9 $a
    fi

    # check tcpdump
    a=`ps | grep tcpdump | awk '{print$1}'`
    if [ $a > 0 ]; then
        kill -9 $a
    fi

    cd ../
    # tcpdump -i eth0 -w target.pcap > tcpdump.log 2>&1 &
    #./server serverIP serverPort   [ipv6Address%networkInterface]:8888   任意串1   任意串2  交易信息位置（中间三个参数用于与课题四交互,需要与client相同）
    LD_LIBRARY_PATH=./lib RUST_LOG=debug ./server 127.0.0.1 5555 [fd01::1%ens33]:8888 fd03::3 fd02::2 ./exchangeImf.json > ./log/server_err.log 2>&1 &
