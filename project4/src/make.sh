
    #!/bin/bash
    
    sh ./stop_server.sh
    cd ./DTP/build/
    make
    
    cp server ../../
    cp client ../../ 
   
    echo finished make and move 
