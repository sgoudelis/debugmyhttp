import redis
from flask import Flask, render_template, request
import json

channel_name_prefix = "httprequests"

app = Flask(__name__)
app.debug = True
redis_queue = redis.StrictRedis(host='localhost', port=6379, db=0)
channel = redis_queue.pubsub()


@app.route('/<bucket>/<path:path>')
def catch_all(bucket, path=None):
    """
    This view gets called by the app being debugged. It then pushed the HttpRequest into redis
    :param bucket:
    :param path:
    :return:
    """

    channel_name = str(channel_name_prefix+"_"+bucket)
    try:
        http_request = {
            'path': str(request.path),
            'method': str(request.method),
            'args': str(request.args),
            'charset': str(request.charset),
            'headers': str(request.headers),
            'data': str(request.data),
            'authorization': str(request.authorization),
            'cookies': str(request.cookies),
            'date': str(request.date),
            'files': str(request.files),
            'pragma': str(request.pragma),
            'scheme': str(request.scheme),
            'get_data': request.get_data(as_text=True, parse_form_data=True)
        }

        #redis_queue.publish(channel_name, json.dumps(http_request))
    except Exception:
        raise

    if app.debug:
        return "pushed into redis httprequest with bucket:path %s:%s" % (bucket, path)
    else:
        return


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
