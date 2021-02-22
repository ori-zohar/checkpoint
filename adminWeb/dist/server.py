__author__ = 's8498053'
import json
import sys
from subprocess import call
import time
import argparse
import getpass
import json
import requests
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

@cross_origin(support_crrdentuals = True)
@app.route('/')
def index():
    return render_template('/index.html')


@app.route('/bini')
def bini():
    return render_template('/bini.html')
@app.route('/server' ,methods =['POST' ,'GET'] )
def server():

    if request.method == "POST":
        name = request.form['name']
        project = request.form['project']
        source = request.form['source']
        destination =request.form['destination']
        port_UDP =request.form['port_UDP']
        port_TCP =request.form['port_TCP']
        Link_type =request.form['Link_type']
        print(source)
        data ={'name' : name ,'project' : project , 'source' :  source , 'destination' : destination, 'port_UDP' : port_UDP , 'port_TCP' : port_TCP , 'Link_type' : Link_type}

        with open(r"C:\Users\s8498053.ARMY\Desktop\WEB_bini\JSON\nonprod.json" ,'w', encoding = "utf-8") as outfile:
            json.dump(data ,outfile)
        print (data)
        return jsonify( data = data )
        return name ,project,source ,destination,port_TCP,port_UDP


@app.route('/tables')
def tables():
    return render_template('/tables.html')
@app.route('/charts')
def charts():
    return render_template('/charts.html')

#################################
# run script name  fw_auto
#################################
@app.route('/fw_auto' ,methods =['POST' ,'GET'])
def fw_auto():
    if request.method == "POST":
        call(["python" ,"fw_auto.py"])
        return render_template('bini.html')
@app.route('/Group' ,methods =['POST' ,'GET'])
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
def create_app(config_filename):
    app = Flask(__name__)
    app.register_error_handler(404 ,page_note_found)
    return app
#######################################
#erorr html 500 not found
#######################################
@app.errorhandler(500)
def internal_server_error(e):
    render_template("500.html" )

def create_app(config_filename):
    app = Flask(__name__)
    app.register_error_handler(500 ,internal_server_error)
    return app

if __name__ == '__main__':
    app.run(debug = True  )