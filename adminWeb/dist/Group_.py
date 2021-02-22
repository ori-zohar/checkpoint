from __future__ import print_function
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
import urllib3
# cpapi is a library that handles the communication with the Check Point management server.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
config =configparser.ConfigParser()
config.sections()
config.read(r"\\hmlotemvfs\Mamram\PublicMamram\תחום טכנולוגיות 2018\MDC\Personal - תיקיות אישיות\ori zohar\checkpoint\test_successfully\_blocking_opening.ini")
from cpapi import APIClient, APIClientArgs
client_args = APIClientArgs(server = "103.8.192.99")
with APIClient(client_args) as client:
     NET_class_A_source = []
     NET_class_B_source = []
     NET_class_C_source = []
     host_source = ["103.17.24.26" , "18.66.24.2"]
     Group_name = input("Enter the name of Group:")
     check_class_C = ["103.23.21.0"]
     host = host_source
     NET_class_C = check_class_C

     add_object =[NET_class_C]
##################################################################
##  data -client
def Class_A (ip_address,list_A):
    global classA_list
    split = ip_address.split(".")
    if (int(split[0]) <= 255) and (int(split[0]) > 0) and ip_address.endswith('0.0.0'):
        list_A.append(ip_address)
        return True
    return False

def Class_B (ip_address ,list_B):
    global classB_list
    split = ip_address.split(".")
    if (int(split[0]) <= 255) and (int(split[0]) > 0) and (int(split[1]) <= 255) and (int(split[1]) > 0) and ip_address.endswith('0.0'):
        list_B.append(ip_address)
        return True
    return False

def Class_C (ip_address ,list_C):
    global classC_list
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
def gateway_ip(ip_addres):
    for ip in ip_addres:

        if Class_A(ip , NET_class_A_source):
            print("ip {0} added to class A source ".format(ip))
        elif Class_B(ip ,NET_class_B_source):
            print("ip {0} added to class B source ".format(ip))
        elif Class_C(ip,NET_class_C_source):
            print("ip {0} added to class C source ".format(ip))
        elif Class_Host(ip,host_source):
            print("ip {0} added to class Host source ".format(ip))


##################################################################
#function it goes on the list and adds to all object recognition of his
#paremetr NET : "NET-" add for list NET_source ,NET_destination
#paremetr HOST : "HOST-" add for list HOST_source ,HOST_destination
#paremetr TCP : "TCP-" add for list TCP_client
#paremetr UDP : "UDP-" add for list UDP_client
#paremetr  result list final :    All_service = UDP_client + TCP_client ,source_client = NET_source + HOST_source ,destination_client = NET_destination + HOST_destination
##################################################################
def Association_for_object():
        global host , NET_class_C
        HOST = "HOST-"
        NET= "NET-"
        HOST_source = [HOST + i for i in host_source  ]
        host = HOST_source
        CHECK_class_C = [ NET + x for x in check_class_C]
        NET_class_C = CHECK_class_C


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

def login( username , password ):
        global  session_id
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
        global  session_id1
        session_id = login_res.data['uid']

        session_res = client.api_call("show-session", {}, login_res.data["sid"])
        session_id1 = session_res.data["uid"]
        print(session_id1)
        log(str(datetime.now().strftime(("Session '{}' initialized. session-timeout: {}".format(session_id, login_res.data['session-timeout'])))))



def add_Group(Group_name ,  host):

        add_group_response = client.api_call("add-group",{"name": Group_name,
                                                                "members": host})
        if add_group_response.success is False:
            if "code" in add_group_response.data and "err_validation_failed" == add_group_response.data["code"]:
                    return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(add_group_response.error_message))))
                 return False

        if add_group_response.success is False:
            if "code" in add_group_response.data and "generic_err_object_not_found" == add_group_response.data["code"]:
                    return True
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(add_group_response.error_message))))
                    return False

        if add_group_response.success is False:
            if "code" in add_group_response.data and "err_validation_failed" == add_group_response.data["code"]:
                    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The group object exists in the system ' + host  )))
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(add_group_response.error_message))))
                    return False

        if (add_group_response.status_code == "400"):
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The group there is a sysytem')))

        if add_group_response.success:
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The group:' "{}" 'has been added successfully'.format(add_group_response.data ['name']))))

        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y group :' "{}" '\n{}.format(add_group_response, add_group_response.error_message ')))
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y ' "[{}] {}: {}".format( add_group_response.status_code, add_group_response.data['code'],  add_group_response .data['message']))))

        return add_group_response.data["name"]


def set_Group(Group_name ,add_object):

        set_group_response = client.api_call("set-group", {"name": Group_name, "members": {"add":add_object }})
        if set_group_response.success is False:
            if "code" in set_group_response.data and "generic_err_invalid_parameter" == set_group_response.data["code"]:
                    return True
            else:
                 discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Operation failed:\n{}\nAborting all changes.'.format(set_group_response.error_message))))
                 return False

        if set_group_response.success is False:
            if "code" in set_group_response.data and "generic_err_object_not_found" == set_group_response.data["code"]:
                    return True
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(set_group_response.error_message))))
                    return False

        if set_group_response.success is False:
            if "code" in set_group_response.data and "err_validation_failed" == set_group_response.data["code"]:
                    log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y  The group object exists in the system ' + add_object  )))
            else:
                    discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y '"Operation failed:\n{}\nAborting all changes.".format(set_group_response.error_message))))
                    return False

        if (set_group_response.status_code == "400"):
                log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The group there is a sysytem')))

        if set_group_response.success:
            log(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y The group:' "{}" 'has been added successfully'.format(set_group_response.data ['name']))))

        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y group :' "{}" '\n{}.format(set_group_response, set_group_response.error_message ')))
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y ' "[{}] {}: {}".format( set_group_response.status_code, set_group_response.data['code'],  add_group_response .data['message']))))

        return set_group_response.data["name"]

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
            if "code" in add_host_response.data and "generic_error" == add_host_response.data["code"]:
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
#This method finds the NET_class_C NAME  which has IP address as the given NET_class_C, and clones this NET_class_C.
#param name network class c :  NET_class_C
#return: True on success, otherwise False
def show_all_network_list_class_C (check_class_C):

    show_all_network_list_class_C_res = client.api_query("show-networks", details_level = "full")

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

###################################################################
#param keep_alive: Check Point method  keep_alive
###################################################################
def keep_alive():

    keep_alive_res = client.api_call("keepalive", {})
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
    if verify_res.success:
            print("The rule were verified successfully.\n{}".format(verify_res.data))
    else:
            print("Failed to publish the changes.")


##################################################################
#param publish: Check Point method  publish
###################################################################
def  publish():

    publish_res =client.api_call("publish", {})
    if publish_res.success:
        log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y The changes were published successfully.')))
    else:
         discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to publish the changes.')))


###################################################################
#param disconnect: Check Point method  disconnect
###################################################################
def disconnect():
        disconnect_res = client.api_call("disconnect", {})
        if disconnect_res.success:
                log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y The changes were disconnect successfully.')))
        else:
                discard_write_to_log_file(str(datetime.now().strftime(' -%H-%M -%d_%m_%Y Failed to disconnect the changes.')))

def logout():

        logout_res = client.api_call("logout" , {})
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


def check_if_the_object_exists_host(host ):
    for a in host :
        if show_host(a)is False :
            (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  the object '+ a + '   host  is      found!'))))
        else:
                    add_host(host = a)
                    time.sleep(3)
                    (log(str(datetime.now().strftime('-%H-%M-%d_%m_%Y  The object '+ a + '  exists  add in the system !'))))

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

def main():
    global host
    global log_file
    log_file = open (r"\\hmlotemvfs\Mamram\PublicMamram\תחום טכנולוגיות 2018\MDC\Personal - תיקיות אישיות\ori zohar\checkpoint\logfile\logfile.txt " , 'w+')
    login (username = "admin" , password = "Aa123456")
    check_if_the_object_exists_Class_C(check_class_C = check_class_C)
    publish()
    time.sleep(3)
    Association_for_object()
    print(NET_class_C)
    set_Group(Group_name = Group_name  ,add_object = NET_class_C)
    publish()
    disconnect()
    logout()


    # close the log file
    log_file.close()
    call(["python" ,"discard_sessions.py"])
if __name__ == "__main__":
    main()
