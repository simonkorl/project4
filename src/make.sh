#!/bin/bash
    
sh ./stop_server.sh
cd ./DTP/test-prog/
make
    
cp server ../../
cp client ../../ 
   
echo finished making and copying executables 
