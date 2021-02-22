

import json
import sys
from subprocess import call
from flask import Flask , request ,render_template ,redirect ,Response , json ,jsonify
from  flask_cors import CORS ,cross_origin
import time
import argparse
import getpass
import json
import requests
import asyncio
import asyncio
import sys, os
import logging
from datetime import datetime
from subprocess import call
from logging.handlers import TimedRotatingFileHandler
import configparser
import asyncio
import sys
from flask import Flask , request ,render_template ,redirect ,Response , json ,jsonify
from  flask_cors import CORS ,cross_origin


app = Flask(__name__)
@app.route('/')
@cross_origin(support_crrdentuals = True)
def Group():
    return render_template('/Group.html')
@app.route('/server' ,methods =['POST' ,'GET'] )
def server_Group():
    if request.method == "POST":
        name = request.form['name']
        network = request.form['network']

        data ={'name' : name ,'network' : network}
        with open(r"C:\Users\s8498053.ARMY\Desktop\WEB_bini\JSON\Gdata.json" ,'w', encoding = "utf-8") as outfile:
            json.dump(data ,outfile)
        print (data)
        return jsonify( data = data)
#################################
# run script name  fw_auto
#################################
@app.route('/Group_' ,methods =['POST' ,'GET'])
def Group_():
    if request.method == "POST":
        call(["python" ,"Group_.py"])
        return render_template('Group.html')
#######################################
#erorr html 404 not found
#######################################
@app.errorhandler(404)
def page_note_found(e):
    render_template("404.html" )
def create_app_404(config_filename):
    app = Flask(__name__)
    app.register_error_handler(404 ,page_note_found)
    return app
#######################################
#erorr html 500 not found
#######################################
@app.errorhandler(500)
def internal_server_error(e):
    render_template("500.html" )

def create_app_500(config_filename):
    app = Flask(__name__)
    app.register_error_handler(500 ,internal_server_error)
    return app

if __name__ == '__main__':
    app.run(debug = True )