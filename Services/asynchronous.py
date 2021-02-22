import datetime
import tornado
import tornado.ioloop
from tornado.httpclient import HTTPClient ,AsyncHTTPClient
def asynchronous_fetch(url):
    http_client =AsyncHTTPClient()
    def handle_response(response):
        print ("asynchronous server said "%response.body)
        http_client.fetch(url , callback = handle_response )