from tornado.websocket import WebSocketHandler, WebSocketClosedError
import tornado.websocket
import tornado.web
import tornado.httpserver
import tornado.options
import brukva
import logging
import random
import json
import redis
from tornado import gen

tornado.options.define("address", default="0.0.0.0", help="address to listen on", type=str)
tornado.options.define("port", default=5000, help="port to listen on", type=int)
tornado.options.define("redishost", default="127.0.0.1", help="redis server", type=str)
tornado.options.define("redisport", default=6379, help="redis port", type=int)
tornado.options.define("redisdb", default=0, help="redis database", type=int)
tornado.options.define("redispassword", default="", help="redis server password", type=str)
tornado.options.define("channelttl", default=3000, help="redis hash key ttl", type=int)
tornado.options.define("clientlimit", default=40, help="client keys limit per ip", type=int)

hash_set_prefix = "client#"
client_ip_prefix = "client_ip#"
channel_name_prefix = "httprequests"


def generate_marker_key():
    """
    Generate a key
    :return:
    """
    unique_hash = hex(random.getrandbits(128))[2:10]
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
        self.redis_sync_connection.incrby(client_ip_prefix+str(client_ip), 1)

        # finish the request
        self.finish(json.dumps({'key': unique_hash}))


class LogView(tornado.web.RequestHandler):
    """
    View for the logger where the user will observe HTTP calls
    """
    def get(self, bucket):
        items = [bucket]
        self.render("templates/log.html", title="Logger", items=items)


class HomeView(tornado.web.RequestHandler):
    """
    View for the logger where the user will observe HTTP calls
    """
    def get(self):
        items = []
        self.render("templates/index.html", title="Logger", items=items)


class LogWebSocket(BaseLogWebSocket):
    """
    Websockets interface
    """
    @gen.engine
    def open(self, bucket='root'):

        channel_name = str(channel_name_prefix+"#"+bucket)

        self.redis_async_connection = brukva.Client(host=tornado.options.options.redishost,
                                                    port=tornado.options.options.redisport,
                                                    password=tornado.options.options.redispassword,
                                                    selected_db=tornado.options.options.redisdb)

        # connect to redis
        self.redis_async_connection.connect()

        # subscribe
        self.redis_async_connection.subscribe(channel_name)

        self.redis_async_connection.listen(self.on_message)
        logging.info('New viewer connected to observe flow for channel: %s' % channel_name)

    def on_message(self, message):
        try:
            if type(message) == unicode:
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
        )

        # constructor
        tornado.web.Application.__init__(self, handlers, **settings)

if __name__ == "__main__":
    tornado.options.parse_command_line()

    application = Application()

    application.listen(tornado.options.options.port, address=tornado.options.options.address)

    tornado.ioloop.IOLoop.instance().start()
