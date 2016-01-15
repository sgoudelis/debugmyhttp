from tornado.websocket import WebSocketHandler, WebSocketClosedError
import tornado.websocket
import tornado.web
import tornado.httpserver
import tornado.options
import brukva
import logging
import random
import json
from tornado import gen

tornado.options.define("address", default="0.0.0.0", help="address to listen on", type=str)
tornado.options.define("port", default=5000, help="port to listen on", type=int)
tornado.options.define("redishost", default="127.0.0.1", help="redis server", type=str)
tornado.options.define("redisport", default=6379, help="redis port", type=int)
tornado.options.define("redisdb", default=0, help="redis database", type=int)
tornado.options.define("redispassword", default="", help="redis server password", type=str)
tornado.options.define("channelttl", default=300, help="redis hash key ttl", type=int)

hash_set_prefix = 'client#'
channel_name_prefix = "httprequests"


class BaseHashViewRequestHandler(tornado.web.RequestHandler):
    client = None


class BaseLogWebSocket(WebSocketHandler):
    client = None


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

        unique_hash = hex(random.getrandbits(128))[2:10]

        self.client = brukva.Client(host=tornado.options.options.redishost, port=tornado.options.options.redisport,
                                    password=tornado.options.options.redispassword,
                                    selected_db=tornado.options.options.redisdb)

        # connect to redis
        self.client.connect()

        self.client.setex(hash_set_prefix+unique_hash, tornado.options.options.channelttl, 1)

        self.finish(json.dumps({'key': unique_hash}))


class LogView(tornado.web.RequestHandler):
    """
    View for the logger where the user will observe HTTP calls
    """
    def get(self, bucket):
        items = [bucket]
        self.render("templates/log.html", title="Logger", items=items)


class LogWebSocket(BaseLogWebSocket):
    """
    Websockets interface
    """
    @gen.engine
    def open(self, bucket='root'):

        channel_name = str(channel_name_prefix+"#"+bucket)

        self.client = brukva.Client(host=tornado.options.options.redishost, port=tornado.options.options.redisport,
                                    password=tornado.options.options.redispassword,
                                    selected_db=tornado.options.options.redisdb)

        # connect to redis
        self.client.connect()

        # Subscribe to the given chat room.
        self.client.subscribe(channel_name)

        self.client.listen(self.on_message)
        logging.info('New viewer connected to observe flow %s' % channel_name)

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
