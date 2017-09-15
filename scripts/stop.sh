ps -ef | grep fs.jar | grep -v grep | awk '{print $2}' | xargs kill -s 9

