from __future__ import print_function

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# A package for reading user and password from a configuration file.
import util
import con
# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs

def get_objects(api_client, filter, offset, limit, object_type, details_level="uid"):
    get_objects_response = api_client.api_call("show-objects",
                                        {"filter": filter,
                                        "limit": limit,
                                        "offset": offset,
                                        "type": object_type,
                                        "details-level": details_level})
    if get_objects_response.success is False:
        print("Failed to show-objects. Error:\n{}".format(get_objects_response.error_message))
        exit(1)

    objects_list = []
    for obj in get_objects_response.data["objects"]:
        objects_list.append(obj["name"])

    print('objects_list Length: {}'.format(len(objects_list)))
    if objects_list:
        print('\t[' + objects_list[0] + '...' + objects_list[-1] + ']')

    if get_objects_response.data["total"]:
        print("show-objects response from {} to {} and total of {}".format(
            get_objects_response.data["from"],
            get_objects_response.data["to"],
            get_objects_response.data["total"]))

    return objects_list

def add():
    username, password = util.get_credentials_access()

    client_args = APIClientArgs()

    with APIClient(client_args) as client:
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        login_res = client.login(username, password)#, payload={"session-timeout":60*60}

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        session_id = login_res.data['uid']
        print("Session '{}' initialized. session-timeout: {}".format(session_id, login_res.data['session-timeout']))

        limit = 50
        offset = items = 0
        for i in range(2):
            members_group = []
            for j in range(10):
                offset = j * limit + items
                hosts_list = get_objects(client, "H-13.", offset, limit, "host", details_level="standard")

                networks_list = get_objects(client, "N-103.", offset, limit, "network", details_level="standard")

                group_name = 'SG-' + str(j+1) + '-NG' + str(i+1)
                add_simple_group_resp = client.api_call("add-group",
                                                        {"name": group_name,
                                                        "members": hosts_list + networks_list})

                if add_simple_group_resp.success is False:
                    print("Failed to add-group: {}. Error:\n{}".format(group_name, add_simple_group_resp.error_message))
                    exit(1)

                members_group.append(add_simple_group_resp.data["uid"])
                print("add-group response: group name: {} and type: {}".format(add_simple_group_resp.data["name"], add_simple_group_resp.data["type"]))

            items = offset + limit
            nested_group_name = 'NG-' + str(i+1)
            print("... Now adding nested group " + nested_group_name)
            add_nested_group_resp = client.api_call("add-group",{"name": nested_group_name,
                                                                "members": members_group})

            if add_nested_group_resp.success:
                print("The nested group: '{}' has been added successfully".format(add_nested_group_resp.data["name"]))
            else:
                print("Failed to add-group: '{}', Error:\n{}".format(nested_group_name, add_nested_group_resp.error_message))

        print("Now, publishing the result ... REMEMBER session_id: {}!!!".format(session_id))

        # publish the result
        publish_res = client.api_call("publish", {})
        if publish_res.success:
            print("The changes were published successfully")
        else:
            print("Failed to publish the changes. \n" + publish_res.error_message)
