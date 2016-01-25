from tornado.websocket import WebSocketHandler, WebSocketClosedError
import tornado.websocket
import tornado.web
import tornado.httpserver
import tornado.options
import brukva
import logging
import json
import redis
import os
import uuid
from tornado import gen

tornado.options.define("address", default="0.0.0.0", help="address to listen on", type=str)
tornado.options.define("port", default=5000, help="port to listen on", type=int)
tornado.options.define("redishost", default="127.0.0.1", help="redis server", type=str)
tornado.options.define("redisport", default=6379, help="redis port", type=int)
tornado.options.define("redisdb", default=0, help="redis database", type=int)
tornado.options.define("redispassword", default="", help="redis server password", type=str)
tornado.options.define("channelttl", default=3600, help="redis hash key ttl", type=int)
tornado.options.define("clientlimit", default=10, help="client keys limit per ip", type=int)
tornado.options.define("requestlimit", default=50, help="request limit per marker key", type=int)
tornado.options.define("historylength", default=10, help="list of last N http requests", type=int)

hash_set_prefix = "client#"
client_ip_prefix = "client_ip#"
channel_name_prefix = 'httprequests#'
client_history = 'client_history#'

def generate_marker_key():
    """
    Generate a key
    :return:
    """
    #unique_hash = hex(random.getrandbits(128))[2:10]
    unique_hash = str(uuid.uuid4().hex)[:10]
    return unique_hash


class BaseHashViewRequestHandler(tornado.web.RequestHandler):
    redis_async_connection = None
    redis_sync_connection = None


class BaseLogWebSocket(WebSocketHandler):
    redis_async_connection = None
    redis_sync_connection = None


class CatchAllView(tornado.web.RequestHandler):
    """
    RequestHandler view for catch all
    """
    def get(self):
        self.finish()

    def post(self):
        self.finish()

    def update(self):
        self.finish()

    def delete(self):
        self.finish()


class GenerateHashView(BaseHashViewRequestHandler):
    """
    View for generating hash
    """
    def get(self):

        unique_hash = generate_marker_key()

        self.redis_sync_connection = redis.StrictRedis(host=tornado.options.options.redishost,
                                                       port=tornado.options.options.redisport,
                                                       password=tornado.options.options.redispassword,
                                                       db=tornado.options.options.redisdb)

        # get real ip address
        client_ip = self.request.headers.get('X-Forwarded-For', self.request.headers.get('X-Real-Ip',
                                                                                         self.request.remote_ip))

        # check how many keys are created from the same ip address
        try:
            client_hits = int(self.redis_sync_connection.get(client_ip_prefix+str(client_ip)))
        except TypeError:
            client_hits = 0

        if client_hits > tornado.options.options.clientlimit:
            self.finish(json.dumps({'error': "limit reached"}))
            return

        # create a value for the key
        value = {'ip': client_ip}

        # set the key in redis
        self.redis_sync_connection.setex(hash_set_prefix+unique_hash, tornado.options.options.channelttl,
                                         json.dumps(value))

        # set the ip as key to keep track how many key there are for that ip
        if not self.redis_sync_connection.exists(client_ip_prefix+str(client_ip)):
            self.redis_sync_connection.setex(client_ip_prefix+str(client_ip), tornado.options.options.channelttl, 1)

        self.redis_sync_connection.incrby(client_ip_prefix+str(client_ip), 1)

        # finish the request
        self.finish(json.dumps({'key': unique_hash}))


class LogView(tornado.web.RequestHandler):
    """
    View for the logger where the user will observe HTTP calls
    """
    def get(self, bucket):
        vals = {'bucket': bucket, 'request_limit': tornado.options.options.requestlimit}
        self.render("templates/log.html", title="Logger", items=vals)


class HomeView(tornado.web.RequestHandler):
    """
    View for the logger where the user will observe HTTP calls
    """
    def get(self):
        vals = {'bucket': "", 'request_limit': tornado.options.options.requestlimit}
        self.render("templates/index.html", title="Logger", items=vals)


class LogWebSocket(BaseLogWebSocket):
    """
    Websockets interface
    """
    channel_name = None

    @gen.engine
    def open(self, bucket='root'):

        self.channel_name = str(channel_name_prefix+bucket)

        self.redis_async_connection = brukva.Client(host=tornado.options.options.redishost,
                                                    port=tornado.options.options.redisport,
                                                    password=tornado.options.options.redispassword,
                                                    selected_db=tornado.options.options.redisdb)

        # connect to redis
        self.redis_async_connection.connect()

        # check for limits first
        self.redis_async_connection.get('counter#'+bucket, self.close_connection_on_limit)

        # check for limits first
        self.redis_async_connection.lrange('client_history#'+bucket, 0, tornado.options.options.historylength,
                                           self.send_request_history)

        # subscribe
        self.redis_async_connection.subscribe(self.channel_name)

        self.redis_async_connection.listen(self.on_message)

        logging.info('New viewer connected to observe flow for channel: %s' % self.channel_name)

    def send_request_history(self, request_list):
        """
        send a the last N HTTP requests made
        :param request_list:
        :return:
        """

        for request in reversed(request_list):
            self.write_message(request)

    def close_connection_on_limit(self, counter):
        """

        :param counter:
        :return:
        """
        if counter is None or int(counter) >= int(tornado.options.options.requestlimit):
            message = {'type': 'alert', 'message': 'this marker key is expired or does not exist',
                       'request_limit': tornado.options.options.requestlimit,
                       'request_count': counter}
            self.write_message(message)

        return

    def on_message(self, message):
        try:
            if type(message) == brukva.exceptions.ResponseError:
                logging.error(message)
            elif type(message) == unicode:
                self.write_message(message)
            else:
                self.write_message(message.body)
        except WebSocketClosedError, e:
            logging.warn('WebsocketClosedError occured %s' % e.message)

    def on_close(self):
        logging.info('Websocket closed')


class Application(tornado.web.Application):
    """
    Main Class for this application holding everything together.
    """

    def __init__(self):

        # url routing
        handlers = [
            (r'/', HomeView),
            (r'/generatekey', GenerateHashView),
            (r'/log/([a-zA-Z0-9]*)$', LogView),
            (r'/log/([a-zA-Z0-9]*)/ws', LogWebSocket),
            (r'/.*', CatchAllView),
        ]

        # settings
        settings = dict(
                auto_reload=True,
                debug=True,
                static_path=os.path.join(os.path.dirname(__file__), "static")
        )

        # constructor
        tornado.web.Application.__init__(self, handlers, **settings)

if __name__ == "__main__":
    tornado.options.parse_command_line()

    application = Application()

    application.listen(tornado.options.options.port, address=tornado.options.options.address)

    tornado.ioloop.IOLoop.instance().start()
