from pcapy import open_live, findalldevs, PcapError
from impacket.ImpactDecoder import *
import argparse
import redis
import json
import datetime
from sys import platform as _platform

parser = argparse.ArgumentParser(description='command line options')

parser.add_argument('-i', '--interface', dest='interface', action='store',
                    default='lo0', help='select interface to capture HTTP requests on')

parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                    default=False, help='be more verbose, show HTTP requests as they are captured')

parser.add_argument('-o', '--redishost', dest='redishost', action='store',
                    default='localhost', help='redis server hostname')

parser.add_argument('-p', '--redisport', dest='redisport', action='store',
                    default=6379, help='redis server port')

parser.add_argument('-b', '--redisdb', dest='redisdb', action='store',
                    default=0, help='redis server database')

parser.add_argument('-s', '--redispassword', dest='redispassword', action='store',
                    default='', help='redis server password')

parser.add_argument('-n', '--sniffport', dest='sniffport', action='store',
                    default=80, help='sniffer port')

parser.add_argument('-c', '--promiscuous', dest='promiscuous', action='store_true',
                    default=False, help='use promiscuous mode')

parser.add_argument('-l', '--requestlimit', dest='requestlimit', action='store',
                    default=50, help='request limit per key')

parser.add_argument('-e', '--channelttl', dest='channelttl', action='store',
                    default=3600, help='TTL for the channel (set of keys in redis per session)')

parser.add_argument('-t', '--historylength', dest='historylength', action='store',
                    default=10, help='number of HTTP requests to keep into a queue for historical purposes')

options = parser.parse_args()

redis_conn = redis.Redis(host=options.redishost, port=options.redisport, db=options.redisdb,
                         password=options.redispassword)

hash_set_prefix = 'client#'
counter_prefix = 'counter#'
channel_name_prefix = "httprequests#"


def get_client_hashes():
    """
    Return a list of hashes that were registered by clients
    :return:
    """
    try:
        client_hashes = redis_conn.keys('client#*')
        hashes_list = []

        for client_hash in client_hashes:
            hashes_list.append(client_hash[len(hash_set_prefix):])
    except Exception, e:
        print e

    return hashes_list


def search_for_hash(hash_list, http_request):
    """
    Search for the hash in the HTTP request and return the found hash
    :param hash_list:
    :param http_request:
    :return:
    """
    for client_hash in hash_list:
        if client_hash in http_request:
            return client_hash

    return False


def log(message, force=False):
    """
    Print message
    :param message:
    :param force:
    :return:
    """
    if options.verbose or force:
        print message


def get_raw_http_request(packet):
    """
    Decode payload with ImpactDecoder
    :param packet:
    :return raw_http_request:
    """
    decoded_packet = EthDecoder().decode(packet)
    raw_http_request = decoded_packet.get_packet()

    # return http request substring
    return raw_http_request


def html_encode(c):
    """
    Simple HTML encoding to defuse JS tags
    :param c:
    :return:
    """
    html_chars = (
        ('&', '&amp;'),
        ("'", '&#39;'),
        ('"', '&quot;'),
        ('>', '&gt;'),
        ('<', '&lt;'),
    )
    for code in html_chars:
        c = c.replace(code[0], code[1])
    return c


def main():
    """
    Main loop
    :return:
    """

    http_methods = ['GET', 'POST', 'UPDATE', 'PUT', 'DELETE', 'HEAD', 'OPTIONS',
                    'get', 'post', 'update', 'put', 'delete', 'head', 'options']

    devices = findalldevs()
    print("Available devices: %s " % devices)
    print("Capturing on %s..." % options.interface)

    sniffer = open_live(options.interface, 65536, options.promiscuous, 100)
    sniffer.setfilter("tcp dst port " +
                      str(options.sniffport)+" and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

    while True:
        try:
            (header, packet) = sniffer.next()
        except PcapError:
            continue
        else:
            raw_http_request = get_raw_http_request(packet)
            hashes_list = get_client_hashes()

            # search for the hash in the raw request
            client_hash = search_for_hash(hashes_list, raw_http_request)

            # if hash is found process it
            if client_hash:

                channel_name = channel_name_prefix+client_hash

                # get request count for hash key
                try:
                    request_count = int(redis_conn.get(counter_prefix+str(client_hash)))
                except TypeError:
                    request_count = 0

                # check to see if we are over the limit
                if int(request_count) >= int(options.requestlimit):
                    message = "Limit of %s reached for key %s " % (options.requestlimit, client_hash)
                    log(message, True)
                    redis_conn.publish(channel_name, json.dumps({'message': message, 'type': 'alert',
                                                                 'event': 'limit_reached',
                                                                 'request_limit': options.requestlimit,
                                                                 'request_count': request_count}))

                    # delete this key and stop looking for these requests
                    redis_conn.delete(hash_set_prefix+str(client_hash))
                    continue

                log("Found HTTP request for hash %s" % client_hash, True)

                # extract source ip address
                decoder = EthDecoder()
                ethernet_frame = decoder.decode(packet)
                ip_header = ethernet_frame.child()
                if _platform == "linux" or _platform == "linux2":
                    source_ip = ip_header.get_ip_src()
                elif _platform == "darwin":
                    source_ip = ip_header.get_ip_address(2)
                elif _platform == "win32":
                    pass

                """
                # try to find start of HTTP request in the raw string
                pos = 0
                print raw_http_request
                for i in range(0, len(raw_http_request)):
                    print raw_http_request[i]
                    if 31 < ord(raw_http_request[i]) < 127:
                        pos = i
                        print "char: %s pos: %s ord: %s" % (raw_http_request[i], pos, ord(raw_http_request[i]))
                        break
                """

                # try to find start of HTTP request based on HTTP verbs
                for http_method in http_methods:
                    idx = raw_http_request.find(http_method)
                    if idx > -1:
                        raw_http_request = raw_http_request[idx:]
                        break

                # HTML encode
                raw_http_request = html_encode(raw_http_request)

                log(raw_http_request)
                http_request = {'request': raw_http_request, 'source_ip': source_ip,
                                'request_limit': options.requestlimit, 'request_count': request_count,
                                'datetime': str(datetime.datetime.utcnow())}

                # push into queue for history
                qlen = redis_conn.lpush('client_history#'+client_hash, json.dumps(http_request))
                if qlen > options.historylength:
                    redis_conn.rpop('client_history#'+client_hash)

                # push the http request down the pipe
                redis_conn.publish(channel_name, json.dumps(http_request))

                # increase count for hash key
                if not redis_conn.exists(counter_prefix+str(client_hash)):
                    redis_conn.setex(counter_prefix+str(client_hash), 1, options.channelttl)

                redis_conn.incrby(counter_prefix+str(client_hash), 1)


if __name__ == "__main__":
    main()
