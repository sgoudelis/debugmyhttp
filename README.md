# debugmyhttp
Source code of debugmyhttp.com

What is included:

#### bucket.py

The bucket.py is responsible for serving the homepage, the log page, generating marker keys and providing a WebSocket connection to the browser.

Usage: 
```
bucket.py options:

  --address                        address to listen on (default 0.0.0.0)
  --channelttl                     redis hash key ttl (default 3600)
  --clientlimit                    client keys limit per ip (default 10)
  --debug                          set Tornado to debug (default True)
  --historylength                  list of last N http requests (default 50)
  --port                           port to listen on (default 5000)
  --redisdb                        redis database (default 0)
  --redishost                      redis server (default 127.0.0.1)
  --redispassword                  redis server password
  --redisport                      redis port (default 6379)
  --requestlimit                   request limit per marker key (default 50)
```

#### grabber.py

The grapper.py is a pcap sniffer. It sniffs for HTTP traffic coming into any interface searching for the marker keys requested by the UI. If the marker key does not exist in REDIS, not traffic is returned. 

Usage:
```
optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        select interface to capture HTTP requests on
  -v, --verbose         be more verbose, show HTTP requests as they are
                        captured
  -o REDISHOST, --redishost REDISHOST
                        redis server hostname
  -p REDISPORT, --redisport REDISPORT
                        redis server port
  -b REDISDB, --redisdb REDISDB
                        redis server database
  -s REDISPASSWORD, --redispassword REDISPASSWORD
                        redis server password
  -n SNIFFPORT, --sniffport SNIFFPORT
                        sniffer port
  -c, --promiscuous     use promiscuous mode
  -l REQUESTLIMIT, --requestlimit REQUESTLIMIT
                        request limit per key
  -e CHANNELTTL, --channelttl CHANNELTTL
                        TTL for the channel (set of keys in redis per session)
  -t HISTORYLENGTH, --historylength HISTORYLENGTH
                        number of HTTP requests to keep into a queue for
                        historical purposes
  -k HISTORYKEEP, --historykeep HISTORYKEEP
                        seconds to keep the queue that contains the history of
                        HTTP requests
```

#### config/

In the config/ directory you will find sample configuration files for Nginx and Supervisor. 
