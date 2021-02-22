from __future__ import print_function
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
import tornado
import tornado.ioloop
from tornado.httpclient import HTTPClient ,AsyncHTTPClient

# cpapi is a library that handles the communication with the Check Point management server.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
config =configparser.ConfigParser()
config.sections()
config.read(r"C:\Users\s8498053.ARMY\Desktop\WEB_bini\python\_blocking_opening.ini")
from cpapi import APIClient , APIClientArgs
client_args = APIClientArgs(server = "")
with APIClient(client_args) as client:

#################################################################
#data fot client
#################################################################
    with open(r"C:\Desktop\WEB_bini\JSON\nonprod.json") as json_file:
        global project , source ,destination ,port_TCP ,port_UDP
        data = json.load(json_file)
        name =data['name']
        project = data['project']
        client_source = data['source']
        client_destination = data['destination']
        port_TCP = data['port_TCP']
        port_UDP = data['port_UDP']
        Link_type = data['Link_type']

#################################################################
    #policy = policy
    url = "https://"
    name_project = project
    source = client_source
    destination = client_destination
    NET_class_A_source = []
    NET_class_B_source = []
    NET_class_C_source = []
    NET_class_A_destination = []
    NET_class_B_destination = []
    NET_class_C_destination = []
    host_source =[]
    host_destination = []
    rule_name = name
    PORT_TCP = [port_TCP ]
    PORT_UDP = [port_UDP ]

    global All_service
    global source_client
    global destination_client
##############################################################


def Class_A (ip_address,list_A):
    split = ip_address.split(".")
    if (int(split[0]) <= 255) and (int(split[0]) > 0) and ip_address.endswith('0.0.0'):
        list_A.append(ip_address)
        return True
    return False

def Class_B (ip_address ,list_B):
    split = ip_address.split(".")
    if (int(split[0]) <= 255) and (int(split[0]) > 0) and (int(split[1]) <= 255) and (int(split[1]) > 0) and ip_address.endswith('0.0'):
        list_B.append(ip_address)
        return True
    return False

def Class_C (ip_address ,list_C):

    split = ip_address.split(".")
    if (int(split[0]) <= 255) and (int(split[0]) > 0) and (int(split[1]) <= 255) and (int(split[1]) > 0) and (int(split[2]) <= 255) and (int(split[2]) > 0) and ip_address.endswith('.0'):
        list_C.append(ip_address)
        return True
    return False

def Class_Host (ip_address,list_Host):
    global classHOSTS_list
    split = ip_address.split(".")
    if (int(split[0]) <= 255) and (int(split[0]) >= 0) and (int(split[1]) <= 255) and (int(split[1]) >= 0) and (int(split[2]) <= 255) and (int(split[2]) >= 0) and (int(split[3]) <= 255) and (int(split[3]) > 0):
        list_Host.append(ip_address)
        return True
    return False

def gateway_ip_source(client_ip_source):
    for ip in client_ip_source:

        if Class_A(ip , NET_class_A_source):
            print("ip {0} added to class A source ".format(ip))
        elif Class_B(ip ,NET_class_B_source):
            print("ip {0} added to class B source ".format(ip))
        elif Class_C(ip,NET_class_C_source):
            print("ip {0} added to class C source ".format(ip))
        elif Class_Host(ip,host_source):
            print("ip {0} added to class Host source ".format(ip))

def gateway_ip_destination(client_ip_destination):
    for i in client_ip_destination:

        if Class_A(i ,  NET_class_A_destination):
            print("ip {0} added to class A destination ".format(i))
        elif Class_B(i ,NET_class_B_destination):
            print("ip {0} added to class B destination ".format(i))
        elif Class_C(i,NET_class_C_destination):
            print("ip {0} added to class C destination " .format(i))
        elif Class_Host(i,host_destination):
            print("ip {0} added to class Host destination ".format(i))

##################################################################
#function it goes on the list and adds to all object recognition of his
#paremetr NET : "NET-" add for list NET_source ,NET_destination
#paremetr HOST : "HOST-" add for list HOST_source ,HOST_destination
#paremetr TCP : "TCP-" add for list TCP_client
#paremetr UDP : "UDP-" add for list UDP_client
#paremetr  result list final :    All_service = UDP_client + TCP_client ,source_client = NET_source + HOST_source ,destination_client = NET_destination + HOST_destination
##################################################################

def Association_for_object():
    global All_service
    global source_client
    global destination_client
    NET= "NET-"
    HOST = "HOST-"
    TCP ="TCP-"
    UDP = "UDP-"
    NET_source= [ NET + x for x in NET_class_A_source + NET_class_B_source + NET_class_C_source ]
    NET_destination =[NET + i for i in NET_class_A_destination + NET_class_B_destination + NET_class_C_destination]
    HOST_source = [HOST + i for i in host_source  ]
    HOST_destination = [HOST + i for i in host_destination]
    TCP_client =[TCP + w for w in PORT_TCP]
    UDP_client =[UDP + w for w in PORT_UDP]
    All_service = UDP_client + TCP_client
    source_client = NET_source + HOST_source
    destination_client = NET_destination + HOST_destination
    return [All_service, source_client,destination_client]

###################################################################
# performs a 'login' API call to the management server
# The API client, would look for the server's certificate SHA1 fingerprint in a file.
# If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
# In case the user does not accept the fingerprint, exit the program.
# param username: Check Point admin name
# param password: Check Point admin password
# sessions is responsible for (sid = uid) of sessions the initial of login
# return: True on success, other wise False
###################################################################

def login( username , password):
        ###
        #"domain" :army.secret
       # getting details from the user
        api_server = config['server.checkpoint']['API_server']
        username = config['User']['user_APP']
        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Logging in to server {}...'.format(api_server))))
        if sys.stdin.isatty():
            password = config['password']['password_APP']

        else:
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Attention! Your password will be shown on the screen!')))
            password = config['password']['password_APP']

        if client.check_fingerprint() is False:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  Could not get the servers fingerprint - Check connectivity with the server.')))
                exit(1)

            # login to server:
        login_res = client.login(username, password)
        synchronous_fetch(url = url ,response = login_res )

        if login_res.success is False:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Login failed:\n{}'.format(login_res.error_message))))
                exit(1)

        if client.check_fingerprint() is False:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Could not get the servers fingerprint - Check connectivity with the server.')))
                exit(1)
            # login to server:
        login_res = client.login(username, password)

        if login_res.success is False:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Login failed:\n{}'.format(login_res.error_message))))
                exit(1)
        session_id = login_res.data['uid']

        session_res = client.api_call("show-sessions", {}, login_res.data["sid"])
        log(str(datetime.now().strftime(("Session '{}' initialized. session-timeout: {}".format(session_id, login_res.data['session-timeout'])))))

###################################################################
# This function is responsible for follow up after creating sessions and deleting of sessions after  the operation
# return: True on success, other wise False
###################################################################
def  sessions_discard ():
    show_sessions_res = client.api_query("show-sessions", "full")
    synchronous_fetch(url = url ,response = show_sessions_res )

    if not show_sessions_res.success:
        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to retrieve the sessions')))
        return

    for sessionObj in show_sessions_res.data:
            # Ignore sessions that were not created with WEB APIs or CLI

        if sessionObj["application"] != [ "WEB_API"] :
                continue

        discard_res = client.api_call("discard", {"uid":sessionObj ['uid']})
        if discard_res.success:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Session "{}" discarded successfully'.format(sessionObj['uid']))))
        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Session "{}" failed to discard '.format(sessionObj['uid']))))

###################################################################
# This function is responsible for add a rule to the of the "Network" layer
# param rule_name: rule_name (string SP- number of appeal )
# param source: original source ip (string NET- ip address)
# param destination: original destination ip ((string NET- ip address))
# param all_service: all_service - This list contains all port that need to the law also of TCP and port UDP   (string TCP/UDP- number OF PORT)
# return: True on success, other wise False
###################################################################

def add_access_rule(rule_name , source_client , destination_client , All_service ):

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Creating a new rule {}'.format(rule_name))))
        # add a rule to the top of the "Network" layer
        add_rule_response = client.api_call("add-access-rule",
                                            {"name":"S-" + rule_name,
                                            "layer": "Network",
                                            "source": source_client,
                                            "destination":  destination_client,
                                            "action": "Accept",
                                            "service": All_service,
                                            "track":"none",
                                            "position":{
                                                "bottom" :name_project,
                                                },
                                            })
        synchronous_fetch(url = url ,response = add_rule_response)


        if add_rule_response.success:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule: "{}" has been added successfully'.format(rule_name))))
        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule : " {}" \n{}'.format(add_rule_response, add_rule_response.error_message ))))
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The rule :[{}] {}: {}'.format( add_rule_response.status_code, add_rule_response.data['code'],  add_rule_response .data['message']))))

        if add_rule_response.success is False:
            if "code" in add_rule_response.data and "generic_err_object_not_found" == add_rule_response.data["code"]:
                return True
            else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed :\n{}\nAborting all changes.'.format(add_rule_response.error_message))))
                return False

        if (add_rule_response.status_code == 400):
             log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The Rule there is a sysytem')))

        res =client.api_call( "publish" , {} )
        if res.success is False:
            discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Publish failed. Error :\n{}\nAborting all changes.'.format(res.error_message))))

        return add_rule_response.data["uid"]

###################################################################
# This function is responsible for search a rule to the of the "Network" layer
# param rule_name: rule_name (string SP- number of appeal )
# param source: original source ip (string NET- ip address)
# param destination: original destination ip ((string NET- ip address))
# param all_service: all_service - This list contains all port that need to the law also of TCP and port UDP   (string TCP/UDP- number OF PORT)
# return: True on success, other wise False
###################################################################

def search_access_rule(rule_name, source_client, destination_client, All_service):
    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Creating a new rule {}'.format(rule_name))))
    # search a rule to the top of the "Network" layer
    search_rule_response = client.api_call("show-access-rulebase",
                                           {
                                               "offset": 0,
                                               "limit": 20,
                                               "name": "Network",
                                               "details-level": "standard",
                                               "use-object-dictionary": True,
                                               "filter":(rule_name, source_client, destination_client, All_service)
                                           }
                                        )
    synchronous_fetch(url=url, response=search_rule_response)

    if search_rule_response.success:
        log(str(
            datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule: "{}" has been added successfully'.format(rule_name))))
    else:
        discard_write_to_log_file(str(datetime.now().strftime(
            ' -%H-%M -%d_%m_%Y The rule : " {}" \n{}'.format(search_rule_response, search_rule_response.error_message))))
        discard_write_to_log_file(str(datetime.now().strftime(
            ' -%H-%M -%d_%m_%Y  The rule :[{}] {}: {}'.format(search_rule_response.status_code,
                                                              search_rule_response.data['code'],
                                                              search_rule_response.data['message']))))

    if search_rule_response.success is False:
        if "code" in search_rule_response.data and "generic_err_object_not_found" == search_rule_response.data["code"]:
            return True
        else:
            discard_write_to_log_file(str(datetime.now().strftime(
                ' -%H-%M -%d_%m_%Y Operation failed :\n{}\nAborting all changes.'.format(
                    search_rule_response.error_message))))
            return False

    if (search_rule_response.status_code == 400):
        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The Rule there is a sysytem')))

    res = client.api_call("publish", {})
    if res.success is False:
        discard_write_to_log_file(str(datetime.now().strftime(
            ' -%H-%M -%d_%m_%Y Publish failed. Error :\n{}\nAborting all changes.'.format(res.error_message))))

    return search_rule_response.data["uid"]

###################################################################
# This function is responsible for add a rule to the of the "Network" layer
# param rule_name: rule_name (string SP- number of appeal )
# param source: original source ip (string NET- ip address)
# param destination: original destination ip ((string NET- ip address))
# param all_service: all_service - This list contains all port that need to the law also of TCP and port UDP   (string TCP/UDP- number OF PORT)
# return: True on success, other wise False
###################################################################

def set_access_rule(rule_name , source_client , destination_client , All_service ):

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Creating a new rule {}'.format(rule_name))))
        # add a rule to the top of the "Network" layer
        set_rule_response = client.api_call("set-access-rule",
                                            {"name":"S-" + rule_name,
                                            "layer": "Network",
                                            "source": source_client,
                                            "destination":  destination_client,
                                            "action": "Accept",
                                            "service": All_service,
                                            "track":"none",
                                            "position":{
                                                "bottom" :name_project,
                                                },
                                            })
        synchronous_fetch(url = url ,response = set_rule_response)


        if set_rule_response.success:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule: "{}" has been added successfully'.format(rule_name))))
        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule : " {}" \n{}'.format(set_rule_response, set_rule_response.error_message ))))
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The rule :[{}] {}: {}'.format( set_rule_response.status_code, set_rule_response.data['code'],  set_rule_response .data['message']))))

        if set_rule_response.success is False:
            if "code" in set_rule_response.data and "generic_err_object_not_found" == set_rule_response.data["code"]:
                return True
            else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed :\n{}\nAborting all changes.'.format(set_rule_response.error_message))))
                return False

        if (set_rule_response.status_code == 400):
             log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The Rule there is a sysytem')))

        res =client.api_call( "publish",{})
        if res.success is False:
            discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Publish failed. Error :\n{}\nAborting all changes.'.format(res.error_message))))
        return set_rule_response.data["uid"]


###################################################################
# This function is responsible for add a rule to the of the "Network" layer
# param rule_name: rule_name (string SP- number of appeal )
# param source: original source ip (string NET- ip address)
# param destination: original destination ip ((string NET- ip address))
# param all_service: all_service - This list contains all port that need to the law also of TCP and port UDP   (string TCP/UDP- number OF PORT)
# return: True on success, other wise False
#The creation of access rule link_bidirectional
###################################################################

def add_access_rule_link_bidirectional(rule_name , source_client , destination_client , All_service ):

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Creating a new rule {}'.format(rule_name))))
        # add a rule to the top of the "Network" layer
        add_rule_link_bidirectional_response = client.api_call("add-access-rule",
                                            {"name":"S-" + rule_name,
                                            "layer": "Network",
                                            "source": destination_client ,
                                            "destination":  source_client ,
                                            "action": "Accept",
                                            "service": All_service,
                                            "track":"none",
                                            "position":{
                                                "bottom" :name_project,
                                                },
                                            })

        synchronous_fetch(url = url ,response = add_rule_link_bidirectional_response)
        if add_rule_link_bidirectional_response .success is False:
            if "code" in add_rule_link_bidirectional_response .data and "generic_err_object_not_found" == add_rule_link_bidirectional_response .data["code"]:
                return True
            else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed :\n{}\nAborting all changes.'.format(add_rule_link_bidirectional_response .error_message))))
                return False

        if add_rule_link_bidirectional_response.success:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule: "{}" has been added successfully'.format(rule_name))))
        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The rule : " {}" \n{}'.format(add_rule_link_bidirectional_response , add_rule_link_bidirectional_response .error_message ))))
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The rule :[{}] {}: {}'.format( add_rule_link_bidirectional_response.status_code, add_rule_link_bidirectional_response .data['code'],  add_rule_link_bidirectional_response .data['message']))))



        if (add_rule_link_bidirectional_response .status_code == "400"):
             log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The Rule there is a sysytem')))

        res =client.api_call( "publish" , {} )
        if res.success is False:
            discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Publish failed. Error :\n{}\nAborting all changes.'.format(res.error_message))))

        return add_rule_link_bidirectional_response.data["uid"]

###################################################################
#This method finds the NET_class_A NAME  which has IP address as the gi
# ven NET_class_A, and clones this NET_class_A.
#param name network class A :  NET_class_A
#return: True on success, otherwise False
###################################################################

#param name network class A :  NET_class_A
def show_all_network_list_class_A (check_class_A):
    for i in check_class_A:
        show_all_network_list_class_A_res = client.api_query("show-networks", details_level = "full")
        synchronous_fetch(url = url ,response = show_all_network_list_class_A_res)
        if show_all_network_list_class_A_res.success is False:
            if "code" in show_all_network_list_class_A_res.data and "generic_err_object_not_found" == show_all_network_list_class_A_res.data["code"]:
                return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(show_all_network_list_class_A_res.error_message))))
                 return False
        if show_all_network_list_class_A_res.success is False:
            if "code" in show_all_network_list_class_A_res .data and "err_validation_failed" == show_all_network_list_class_A_res.data["code"]:
                    return True
            else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(show_all_network_list_class_A_res.error_message))))
                     return False

        if show_all_network_list_class_A_res.success is False:
            discard_write_to_log_file( "Failed to get show-NETWORK data:\n{}".format(show_all_network_list_class_A_res.error_message))
            return False
        if show_all_network_list_class_A_res.success is False:
                if "code" in show_all_network_list_class_A_res.data and "200" == show_all_network_list_class_A_res.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(show_all_network_list_class_A_res.error_message))))
                     return False
        # go over all the exist NET_class_A and look for NET_class_A with same ip as NET_class_A
        for NET_class_A_object in show_all_network_list_class_A_res.data:
            # if the ip is not as the original host continue looking
            if NET_class_A_object.get("ipv4-address") != check_class_A  :
                continue
            # found host with the same ip as NET_class_A, get the data of the NET_class_A
            check_class_A = NET_class_A_object["name"]
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y host: Found network class B  name: ' + check_class_A + ", with IP: " + check_class_A )))


######################################################################
#This method checks if the new NET_class_A  already exists, and if so the method returns the tuple name and status
#return: True if the NET CLASS A doesn't exist
#False if error occurred
#NAME if the NET_class_A already exists, and the name is the same name of the existing NET_class_A
######################################################################
# check if the NET_class_A already exists, find the NET_class_A name

def show_network_class_A(check_class_A):

    # check if the NETWORK for class A already exists, find the NET_class_A name
    show_network_class_A_res = client.api_call("show-network", {"name" : check_class_A})
    synchronous_fetch(url = url ,response = show_network_class_A_res)
    if show_network_class_A_res.success is False:
        if "code" in show_network_class_A_res.data and "generic_err_object_not_found" == show_network_class_A_res.data["code"]:
            return True
        else:
           discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y'
                                      "Operation failed:\n{}\nAborting all changes.".format(show_network_class_A_res.error_message)))))
           return False

    if show_network_class_A_res.data.get("ipv4-address") == check_class_A or show_network_class_A_res.data.get("ipv6-address") == check_class_A:

        log((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y \n\t The NET_class_A  with the same name and IP already exists,\n\t'
            "going to copy it to the same places as the original NET_class_A"))))
        return show_network_class_A_res.data["name"]
    else:
       discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y' "A network_class_B with the same name but a different IP address "
                                              "already exists, discarding all changes"))))

       return False


###################################################################
#This function is responsible for add object NET_class_A :
#param NET_class_A: NET_class_A (string NET- ip address / 255.0.0.0.0)
#return: True on success AND created add rule , other wise False
###################################################################
def add_network_class_A(check_class_A):
    for i in check_class_A:
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  Creating a new network class A {}...'.format(check_class_A))))
            add_network_class_A_response = client.api_call("add-network",
                                                                {"name" : 'NET-' + check_class_A ,
                                                                "subnet4" : check_class_A ,
                                                                "subnet-mask" : "255.0.0.0", })


            synchronous_fetch(url = url ,response = add_network_class_A_response)
            if add_network_class_A_response.success is False:
                if "code" in add_network_class_A_response.data and "err_validation_failed" == add_network_class_A_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_network_class_A_response.error_message))))
                     return False

            if add_network_class_A_response.success is False:
                if "code" in add_network_class_A_response.data and "generic_error" == add_network_class_A_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_network_class_A_response.error_message))))
                     return False

            if add_network_class_A_response.success is False:
                if "code" in add_network_class_A_response.data and "generic_err_object_not_found" == add_network_class_A_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_network_class_A_response.error_message))))
                return False

            if (add_network_class_A_response.status_code == 400):
                 log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Then network_class_ A there is a sysytem ')))

            if  add_network_class_A_response .success:
                    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The network class A: "{}" has been added successfully'.format( add_network_class_A_response .data['name']))))
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y network : " {}" \n{}'.format(add_network_class_A_response, add_network_class_A_response.error_message ))))
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y [{}] {}: {}'.format( add_network_class_A_response.status_code, add_network_class_A_response.data['code'],  add_network_class_A_response .data['message']))))




###################################################################
#This method finds the NET_class_B NAME  which has IP address as the given NET_class_B, and clones this NET_class_B.
#return: True on success, otherwise False
#param name network class B :  NET_class_B
###################################################################

def show_all_network_list_class_B (check_class_B):

    show_all_network_list_class_B_res = client.api_query("show-networks", details_level = "full")
    synchronous_fetch(url = url ,response = show_all_network_list_class_B_res)
    if show_all_network_list_class_B_res.success is False:
            if "code" in show_all_network_list_class_B_res.data and "generic_err_object_not_found" == show_all_network_list_class_B_res.data["code"]:
                return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(show_all_network_list_class_B_res.error_message))))
                 return False

    if show_all_network_list_class_B_res.success is False:
        discard_write_to_log_file( "Failed to get show-host data:\n{}".format(show_all_network_list_class_B_res.error_message))
        return False
    # go over all the exist NET_class_B and look for NET_class_B with same ip as NET_class_B
    for NET_class_B_object in show_all_network_list_class_B_res.data:
        # if the ip is not as the original host continue looking
        if NET_class_B_object.get("ipv4-address") != check_class_B and NET_class_B_object.get("ipv6-address") != check_class_B :
            continue
        # found host with the same ip as NET_class_B, get the data of the NET_class_B
        check_class_B = NET_class_B_object["name"]
        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y host: Found network class B  name: ' + check_class_B + ", with IP: " + check_class_B )))


######################################################################
#This method checks if the new NET_class_B  already exists, and if so the method returns the tuple name and status
#return: True if the host doesn't exist
#False if error occurred
#NAME if the NET_class_B already exists, and the name is the same name of the existing NET_class_B
######################################################################
# check if the NET_class_B already exists, find the NET_class_B name
def show_network_class_B (check_class_B):

    # check if the host already exists, find the NET_class_B name
    show_network_class_B_res = client.api_call("show-network", {"name" : check_class_B})
    synchronous_fetch(url = url ,response = show_network_class_B_res)
    if show_network_class_B_res.success is False:
        if "code" in show_network_class_B_res.data and "generic_err_object_not_found" == show_network_class_B_res.data["code"]:
            return True
        else:
           discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y'
                                      "Operation failed:\n{}\nAborting all changes.".format(show_network_class_B_res.error_message)))))
           return False

    if show_network_class_B_res.data.get("ipv4-address") == check_class_B or show_network_class_B_res.data.get("ipv6-address") == check_class_B:

        log((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y \n\t The NET_class_B  with the same name and IP already exists,\n\t'
            "going to copy it to the same places as the original NET_class_B"))))
        return show_network_class_B_res.data["name"]
    else:
       discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y' "A network_class_B with the same name but a different IP address "
                                              "already exists, discarding all changes"))))

       return False


###################################################################
#This function is responsible for add object NET_class_B :
#param NET_class_B: NET_class_B (string NET- ip address / 255.255.0.0.0)
#return: True on success AND created  add_network_class_B , other wise False
###################################################################
def add_network_class_B(check_class_B ):
    for o in check_class_B :
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Creating a new network class B {}...'.format(check_class_B))))
            add_network_class_B_response = client.api_call("add-network",
                                                                {"name" : 'NET-' + check_class_B ,
                                                                "subnet4"  : check_class_B ,
                                                                "subnet-mask" : "255.255.0.0", })
            synchronous_fetch(url = url ,response = add_network_class_B_response)
            if add_network_class_B_response.success is False:
                if "code" in add_network_class_B_response.data and "err_validation_failed" == add_network_class_B_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_network_class_B_response.error_message))))
                     return False

            if add_network_class_B_response.success is False:
                    if "code" in  add_network_class_B_response.data  and "generic_err_object_not_found" == add_network_class_B_response.data["code"]:
                            return True
                    else:

                            discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  Operation failed:\n{}\nAborting all changes.'.format(add_network_class_B_response.error_message))))
                            return False

            if (add_network_class_B_response.status_code == 400):
                   log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The network_class_ B there is a sysytem')))

            if add_network_class_B_response.success:
                          log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y NETWORK CLASS B: "{}" has been added successfully '.format(add_network_class_B_response .data['name']))))

            else:
                        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y network : " {}" \n{} '.format(  add_network_class_B_response, add_network_class_B_response.error_message ))))
                        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y"[{}] {}: {}'.format( add_network_class_B_response.status_code, add_network_class_B_response .data['code'],  add_network_class_B_response.data['message']))))




###################################################################
#This method finds the NET_class_C NAME  which has IP address as the given NET_class_C, and clones this NET_class_C.
#param name network class c :  NET_class_C
#return: True on success, otherwise False
def show_all_network_list_class_C (check_class_C):

    show_all_network_list_class_C_res = client.api_query("show-networks", details_level = "full")
    synchronous_fetch(url = url ,response = show_all_network_list_class_C_res)
    if show_all_network_list_class_C_res.success is False:
            if "code" in show_all_network_list_class_C_res.data and "generic_err_object_not_found" == show_all_network_list_class_C_res.data["code"]:
                return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(show_all_network_list_class_C_res.error_message))))
                 return False

    if show_all_network_list_class_C_res.success is False:
        discard_write_to_log_file( "Failed to get show-host data:\n{}".format(show_all_network_list_class_C_res.error_message))
        return False
    # go over all the exist NET_class_C and look for NET_class_C with same ip as NET_class_C
    for NET_class_C_object in show_all_network_list_class_C_res.data:
        # if the ip is not as the original host continue looking
        if NET_class_C_object.get("ipv4-address") != check_class_C and NET_class_C_object.get("ipv6-address") != check_class_C:
            continue
        # found NET_class_C_ with the same ip as NETWORK class C, get the data of the NET_class_C
        check_class_C = NET_class_C_object["name"]
        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y host: Found network class C  name: ' + check_class_C + ", with IP: " + check_class_C )))


######################################################################
#This method checks if the new NET_class_C  already exists, and if so the method returns the tuple name and status
#param name network class c :  NET_class_C
#return: True if the host doesn't exist
#False if error occurred
#NAME if the NET_class_C already exists, and the name is the same name of the existing NET_class_C
######################################################################
# check if the NET_class_C already exists, find the NET_class_C name
def show_network_class_C (check_class_C):


    # check if the host already exists, find the NET_class_C name
    show_network_class_C_res = client.api_call("show-network", {"name" : check_class_C})
    synchronous_fetch(url = url ,response = show_network_class_C_res)
    if show_network_class_C_res.success is False:
        if "code" in show_network_class_C_res.data and "generic_err_object_not_found" == show_network_class_C_res.data["code"]:
            return True
        else:
           discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y'
                                      "Operation failed:\n{}\nAborting all changes.".format(show_network_class_C_res.error_message)))))
           return False

    if show_network_class_C_res.data.get("ipv4-address") == check_class_C or show_network_class_C_res.data.get("ipv6-address") == check_class_C:

        log((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y \n\t The NET_class_C  with the same name and IP already exists,\n\t'
            "going to copy it to the same places as the original NET_class_C"))))
        return show_network_class_C_res.data["name"]
    else:
       discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y' "A host with the same name but a different IP address "
                                              "already exists, discarding all changes"))))

       return False



###################################################################
#This function is responsible for add object NET_class_C :
#param NET_class_C: NET_class_C (string NET- ip address / 255.255.255.0.0)
#return: True on success AND created  add_network_class_C , other wise False
###################################################################
def add_network_class_C (check_class_C ):
    for e in check_class_C :
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  Creating a new network class C {}.... '.format(check_class_C))))
            add_network_class_C_response = client.api_call("add-network",
                                                            {"name" : 'NET-' +  check_class_C  ,
                                                            "subnet4" : check_class_C,
                                                            "subnet-mask" : "255.255.255.0", })
            synchronous_fetch(url = url ,response = add_network_class_C_response)

            if add_network_class_C_response.success is False:
                if "code" in add_network_class_C_response.data and "err_validation_failed" == add_network_class_C_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_network_class_C_response.error_message))))
                     return False

            if add_network_class_C_response.success is False:
                if "code" in add_network_class_C_response.data and "generic_err_object_not_found"  == add_network_class_C_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed : \n{}\nAborting all changes.'.format(add_network_class_C_response.error_message))))
                     return False


            if (add_network_class_C_response.status_code == 400):
                      log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The network_class_ C there is a sysytem ')))

            if add_network_class_C_response .success:
                           log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The NETWORK CLASS C: "{}" has been added successfully '.format(add_network_class_C_response .data['name']))))

            else:
                        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y network: "{}" \n{}'.format( add_network_class_C_response , add_network_class_C_response .error_message))))
                        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y[{}] {}: {}'.format(add_network_class_C_response.status_code,add_network_class_C_response .data['code'], add_network_class_C_response.data['message']))))
            return None


######################################################################
#This method checks if the new port tcp  already exists, and if so the method returns the tuple name and status
#param name tcp port:  port_TCP
#param port: port_TCP
#return: True if the port_TCP doesn't exist
#False if error occurred
#NAME if the port tcp  already exists, and the name is the same name of the existing port tcp
######################################################################
# check if the port tcp already exists, find the port_TCP name

def show_port_TCP (PORT_TCP):
    # check if the host already exists, find the port_TCP name
    show_port_TCP_res = client.api_call("show-service-tcp ", {"name": PORT_TCP})
    synchronous_fetch(url = url ,response = show_port_TCP_res)
    if show_port_TCP_res.success is False:

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The port tcp object exists in the system ' + PORT_TCP  )))
    else:
        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(show_port_TCP_res.error_message))))
        return False



###################################################################
#This function is responsible for add_port_TCP:
#param add_port_TCP: add_port_TCP (string TCP- number OF PORT )
#return: True on success AND created  port_TCP , other wise False
###################################################################
def add_port_TCP(PORT_TCP):

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  Creating a new port TCP {}...'.format(PORT_TCP))))
        add_service_TCP_response = client.api_call("add-service-tcp",
                                                {"name" : 'TCP-' + PORT_TCP ,
                                                "port" : PORT_TCP ,
                                                "session-timeout" : 5})
        synchronous_fetch(url = url ,response = add_service_TCP_response)
        if add_service_TCP_response.success is False:
                if "code" in add_service_TCP_response.data and "err_validation_failed" == add_service_TCP_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_service_TCP_response.error_message))))
                     return False

        if add_service_TCP_response.success is False:
            if "code" in add_service_TCP_response.data and "generic_err_object_not_found" == add_service_TCP_response.data["code"]:
                return True
            else:

                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_service_TCP_response.error_message))))
            return False

        if (add_service_TCP_response.status_code == 400):
           log(str(datetime.now().strftime('-%H-%M -%d_%m_%Y The service there is a sysytem ')))

        if add_service_TCP_response.success:

            log(str(datetime.now().strftime('-%H-%M -%d_%m_%Y The service: "{}" has been added successfully'.format(add_service_TCP_response.data['name']))))

            return True
        else:

            discard_write_to_log_file((str(datetime.now().strftime('-%H-%M -%d_%m_%Y Port: "{}" \n{}'.format(add_service_TCP_response,add_service_TCP_response.error_message)))))
            discard_write_to_log_file((str(datetime.now().strftime('-%H-%M -%d_%m_%Y [{}] {}: {}'.format(add_service_TCP_response.status_code, add_service_TCP_response.data['code'] , add_service_TCP_response.data['message'])))))
        return add_service_TCP_response.data["name"]


######################################################################
#This method checks if the new port udp  already exists, and if so the method returns the tuple name and status
#param name udp port:  port_UDP
#param port: port_UDP
#return: True if the port_UDP doesn't exist
#False if error occurred
#NAME if the port udp  already exists, and the name is the same name of the existing port udp
######################################################################
# check if the port udp already exists, find the port_UDP name


def show_port_UDP(PORT_UDP):

    # check if the host already exists, find the port_UDP name
    show_port_UDP_res = client.api_call("show-service-udp", {"name": PORT_UDP})
    synchronous_fetch(url = url ,response = show_port_UDP_res)
    if show_port_UDP_res.success is False:

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The port tcp object exists in the system ' + PORT_UDP  )))
    else:
        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(show_port_UDP_res.error_message))))
        return False




###################################################################
#This function is responsible for add_port_UDP:
#param add_port_UDP: add_port_UDP (string UDP- number OF PORT )
#return: True on success AND created  port_TCP , other wise False
###################################################################
def add_port_UDP(PORT_UDP):

        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  Creating a new port port_UDP {}...'.format(PORT_UDP))))
        add_service_UDP_response = client.api_call("add-service-udp",
                                                {"name" : 'UDP-' + PORT_UDP,
                                                "port" :PORT_UDP ,
                                                "session-timeout" : 5})
        synchronous_fetch(url = url ,response = add_service_UDP_response)
        if add_service_UDP_response.success is False:
            if "code" in add_service_UDP_response.data and "err_validation_failed" == add_service_UDP_response.data["code"]:
                    return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_service_UDP_response.error_message))))
                 return False


        if add_service_UDP_response.success is False:
            if "code" in add_service_UDP_response.data and "More than one object named" + PORT_UDP  + "exists." == add_service_UDP_response.data["code"]:
                exit(1)

            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_service_UDP_response.error_message))))
                    return False
        if add_service_UDP_response.success is False:
                if "code" in add_service_UDP_response.data and "err_validation_failed" == add_service_UDP_response.data["code"]:
                    return True
                else:
                     discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_service_UDP_response.error_message))))
                     return False

        if add_service_UDP_response.success is False:
            if "code" in add_service_UDP_response.data and "generic_err_object_not_found" == add_service_UDP_response.data["code"]:
                    return True

            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_service_UDP_response.error_message))))
                    return False

        if (add_service_UDP_response.status_code == "400"):
                log((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The service there is a sysytem'))))
        if add_service_UDP_response.success:
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The service: "{}" has been added successfully '.format( add_service_UDP_response.data['name']))))

        else:
                discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Port: "{}" \n{}'.format( add_service_UDP_response,add_service_UDP_response.error_message)))))
                discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y "[{}] {}: {}'.format(add_service_UDP_response.status_code,add_service_UDP_response.data['code'], add_service_UDP_response.data['message'])))))
        return add_service_UDP_response.data["name"]


######################################################################
#This method checks if the new host already exists, and if so the method returns the tuple name and status
#param host_name:  host name
#param host_ip: host
#return: True if the host doesn't exist
#False if error occurred
#NAME if the host already exists, and the name is the same name of the existing host
######################################################################
# check if the host already exists, find the host name

def show_host (host):

    # check if the host already exists, find the host name
    show_host_res = client.api_call("show-host", {"name": host})
    synchronous_fetch(url = url ,response = show_host_res)
    if show_host_res.success is False:
        if "code" in show_host_res.data and "generic_err_object_not_found" == show_host_res.data["code"]:
            return True
        else:
           discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y'
                                      "Operation failed:\n{}\nAborting all changes.".format(show_host_res.error_message)))))
           return False

    if show_host_res.success is False:
            if "code" in show_host_res.data and "err_validation_failed " == show_host_res.data["code"]:
                    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The host object exists in the system ' + host  )))
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(show_host_res.error_message))))
                    return False

    if show_host_res.data.get("ipv4-address") == host or show_host_res.data.get("ipv6-address") == host:
        log((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y \n\tThe host with the same name and IP already exists,\n\t'
            "going to copy it to the same places as the original host"))))
        return show_host_res.data["name"]
    else:
       discard_write_to_log_file((str(datetime.now().strftime(' -%H-%M -%d_%m_%Y' "A host with the same name but a different IP address "
                                              "already exists, discarding all changes"))))

    return False


###################################################################
#This method finds the host uid which has IP address as the given host, and clones this host.
#param cloned_host_ip: host IP
#param cloned_host_name: cloned host name
#param orig_host_ip:  host ip
#return: True on success, otherwise False
###################################################################
def show_all_list_hosts(host):

    show_hosts_res = client.api_query("show-hosts", details_level="full")
    synchronous_fetch(url = url ,response = show_hosts_res)
    if show_hosts_res.success is False:
            if "code" in show_hosts_res.data and "generic_err_object_not_found" == show_hosts_res.data["code"]:
                return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(show_hosts_res.error_message))))
                 return False

    if show_hosts_res.success is False:
            if "code" in show_hosts_res.data and "err_validation_failed" == show_hosts_res.data["code"]:
                    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The host object exists in the system ' + host  )))
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(show_hosts_res.error_message))))
                    return False

    if show_hosts_res.success is False:
        discard_write_to_log_file( "Failed to get show-host data:\n{}".format(show_hosts_res.error_message))
        return False
    # go over all the exist hosts and look for host with same ip as _host
    for host_object in show_hosts_res.data:
        # if the ip is not as the original host continue looking
        if host_object.get("'ip-address'") != host and host_object.get("ipv4-address") != host:
            continue
        # found host with the same ip as host, get the data of the host
        host = host_object["name"]
        log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y host: Found host name: ' + host + ", with IP: " + host )))



###################################################################
#This function is responsible for add_host :
#param add_host: add_host (string HOST- ip address / an example of HOST-196.66.33.22)
#return: True on success AND created  add_host , other wise False
###################################################################

def add_host(host):
   for a in host :
        log(str(datetime.now().strftime('-%H-%M -%d_%m_%Y Creating a new  host {}...'.format(host))))
        add_host_response = client.api_call('add-host', {"name" : 'HOST-' + host ,
                                                           'ip-address': host ,
                                                            })
        synchronous_fetch(url = url ,response = add_host_response)
        if add_host_response.success is False:
            if "code" in add_host_response.data and "err_validation_failed" == add_host_response.data["code"]:
                    return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_host_response.error_message))))
                 return False

        if add_host_response.success is False:
            if "code" in add_host_response.data and "generic_err_object_not_found" == add_host_response.data["code"]:
                    return True
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(add_host_response.error_message))))
                    return False

        if add_host_response.success is False:
            if "code" in add_host_response.data and "err_validation_failed" == add_host_response.data["code"]:
                    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The host object exists in the system ' + host  )))
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(add_host_response.error_message))))
                    return False

        if (add_host_response.status_code == "400"):
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The HOST there is a sysytem')))

        if add_host_response.success:
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The host:' "{}" 'has been added successfully'.format(add_host_response.data ['name']))))

        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y HOST :' "{}" '\n{}.format(add_host_response, add_host_response.error_message ')))
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y ' "[{}] {}: {}".format( add_host_response.status_code, add_host_response.data['code'],  add_host_response .data['message']))))

        return add_host_response.data["name"]

###################################################################
# This method executes 'where-used' command on a given host and returns the command response on success.
# If the original host is not used by any object, the method returns True.
# In case of an error, the method returns False.
# param orig_host_name: original host name
# param orig_host_name: original host name
# return: the places the host is used, True if the host is not used, False in case of an error
# call the where-used API for the object we need to clone
###################################################################


def where_host_used(host):

    where_used = client.api_call("where-used", {"name": host})
    synchronous_fetch(url = url ,response = where_used)
    if where_used.success is False:
        discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to get ' + host + " data:\n{}" .format(where_used.error_message))))
        return False

    # if the object is not being referenced there is nothing to do.
    if where_used.data["used-directly"]["total"] == 0:
        log(str(datetime.now().strftime(' -%H-%M-%d_%m_%Y  ' + host + 'is not used! -- nothing to do' )))
        return True

    return where_used


def Tag(name_project):
    tag_res =client.api_call("add-access-section", {"layer":"Network","position":1 , 'name':name_project ,
                                           })
    if tag_res.success:
        log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y The changes were tag successfully.')))
    else:
         discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to tag the changes.')))

##################################################################
#param keep_alive: Check Point method  keep_alive
###################################################################
def keep_alive():

    keep_alive_res = client.api_call("keepalive", {})
    synchronous_fetch(url = url ,response = keep_alive_res)
    if keep_alive_res.success:
         log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y The changes were keep alive successfully.')))
    else:
          discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to keep alive the changes.')))

##################################################################
#param verify: Check Point method  verify
###################################################################
def verify():
    # Verifies the policy package
    verify_res = client.api_call("verify-policy", {"policy-package" : "standard"})
    synchronous_fetch(url = url ,response = verify_res)
    if verify_res.success:
            print("The rule were verified successfully.\n{}".format(verify_res.data))
    else:
            print("Failed to publish the changes.")


##################################################################
#param publish: Check Point method  publish
###################################################################
def  publish():
    publish_res =client.api_call("publish", {})
    synchronous_fetch(url = url ,response = publish_res)
    if publish_res.success:
        log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y The changes were published successfully.')))
    else:
         discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to publish the changes.')))

###################################################################
#param logout: Check Point method  logout
###################################################################
def logout():

        logout_res = client.api_call("logout" , {})
        synchronous_fetch(url = url ,response = logout_res)
        if logout_res.success:
                log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y The changes were logout successfully.')))
        else:

                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to logout the changes.')))



#logout()
###################################################################
#This method writes message to the log file and print it
#param message: message that will be written to log file
###################################################################
def log(message):
    global log_file
    print(message.encode("utf-8"), file=log_file)
    print(message)


###################################################################
#This method discards the changes for a given api client and save message to the log file
#param message: message that will be written to log file
###################################################################
def discard_write_to_log_file( message):
    """
    :rtype : object
    """

    client.api_call("discard", {})
    log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y' + message)))


###################################################################
#This method writes message to log file close log file and exit the function
#param message: message that will be written to log file
###################################################################
def write_message_close_log_file_and_exit(message):

    global log_file
    log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y' + message)))
    log_file.close()
    exit(1)

###################################################################
# function it looks at the information received a net class A for client
# request for review if object there in the system in function  show_all_network_list_class_A
# after checking the object is in if you  don't access function add_network_class_A  and production
# check_class_A = NET_class_A_source + NET_class_A_destination
# param check_class_A: list which has the values [check_class_A = NET_class_A_source + NET_class_A_destination]
# param NET_class_A_source : this NET_class_A_source is obtained from the client for source type of class A
# param NET_class_A_destination : this NET_class_A_destination is obtained from the client for destination type of class A
# return True :if the rest of the object new
###################################################################

def check_if_the_object_exists_Class_A(check_class_A ):
    for i in check_class_A :
        time.sleep(1)
        if  show_network_class_A(i) is False :
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ i + '  network class A  is   found!'))))
        else:
              add_network_class_A(check_class_A = i )
              time.sleep(3)
              (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  The object '+ i + ' exists not     in the system !' ))))




###################################################################
# function it looks at the information received a net class B for client
# request for review if object there in the system in function  show_all_network_list_class_B
# after checking the object is in if you  don't access function add_network_class_B  and production
# check_class_B = NET_class_B_source + NET_class_B_destination
# param check_class_B: list which has the values [check_class_A = NET_class_A_source + NET_class_A_destination]
# param NET_class_B_source : this NET_class_B_source is obtained from the client for source type of class B
# param NET_class_B_destination : this NET_class_B_destination is obtained from the client for destination type of class B
# return True :if the rest of the object new
###################################################################

def check_if_the_object_exists_Class_B(check_class_B ):
    for o in check_class_B :
        time.sleep(1)
        if show_network_class_B(o) is False :
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ o + '      network class B  is   found!'))))
        else:
            add_network_class_B(check_class_B = o)
            time.sleep(3)
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ o + ' not add  network class B  !'))))

###################################################################
# function it looks at the information received a net class C for client
# request for review if object there in the system in function  show_all_network_list_class_C
# after checking the object is in if you  don't access function add_network_class_C and production
# check_class_C = NET_class_C_source + NET_class_C_destination
# param check_class_C: list which has the values [check_class_C = NET_class_C_source + NET_class_C_destination]
# param NET_class_C_source : this NET_class_C_source is obtained from the client for source type of class C
# param NET_class_C_destination : this NET_class_C_destination is obtained from the client for destination type of class C
# return True :if the rest of the object new
###################################################################

def check_if_the_object_exists_Class_C(check_class_C ):
    for e in check_class_C :
        if show_network_class_C(e) is False:
             (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ e + '   network class C is   found!'))))
        else:
             add_network_class_C(check_class_C = e)
             time.sleep(3)
             (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ e + '  add  network class C !'))))




###################################################################
# function it looks at the information received a host for client.
# request for review if object there in the system in function  show_all_list_hosts.
# after checking the object is in if you  don't access function add_host and production.
# host = host_source + host_destination.
# param check_class_C: list which has the values [host = host_source + host_destination.].
# param host_source : this host_source is obtained from the client for source type of host source.
# param host_destination : this host_destination is obtained from the client for destination type of host destination.
# return True :if the rest of the object new.
###################################################################

def check_if_the_object_exists_host( host ):
    for a in host :
        if show_host(a)is False :
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object ' + a + '   host  is   found!'))))
        else:

                    add_host(host = a)
                    time.sleep(3)
                    (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  The object ' + a + '  exists  add in the system !'))))

###################################################################
# function it looks at the information received a port TCP for client.
# request for review if object there in the system in function  show_port_TCP.
# after checking the object is in if you  don't access function add_port_TCP and production.
# PORT_TCP -data this variable represents the information
# return True :if the rest of the object new.
###################################################################

def check_if_the_object_exists_port_tcp(PORT_TCP):
    for b in PORT_TCP :
        if show_port_TCP(b) is False :
             (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ b + '    port_TCP  is   found!'))))
        else:

            add_port_TCP(PORT_TCP = b)
            time.sleep(3)
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  The objec'+ b + '   add exists  in the system !'))))



###################################################################
# function it looks at the information received a port TCP for client.
# request for review if object there in the system in function  show_port_UDP.
# after checking the object is in if you  don't access function add_port_UDP and production.
# PORT_ UDP - data this variable represents the information
# return True :if the rest of the object new.
###################################################################

def check_if_the_object_exists_port_udp(PORT_UDP):
    for w in PORT_UDP :
        if show_port_UDP(w) is False :
             (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ w + '  PORT_UDP  is   found!'))))
        else:

            add_port_UDP(PORT_UDP = w)
            time.sleep(3)
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  The object '+ w + 'not  exists  in the system !'))))
##################################################################
#synchronous_fetch submit a wait request until you receive a reply
#url : "https://103.8.192.99"
#response :message asynchronous server said
##################################################################
def synchronous_fetch(url ,response):
    http_client =AsyncHTTPClient()
    start_dt = datetime.now()
    response =http_client.fetch(url)
    end_dt = datetime.now()
    (log(str(datetime.now().strftime('the synchronous fetch took seconds'))))

def main():

    global log_file
    global All_service
    global source_client
    global destination_client
    log_file = open (r"C:\Desktop\WEB_bini\log_file\logfile.txt" , 'w+')
    # close the log file
    log_file.close()
    call(["python" , "discard_sessions.py"])
if __name__ == "__main__":
    main()

