
from __future__ import print_function
from cryptography import x509
import getpass
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs


def main():
    # getting details from the user
    api_server = "103.8.192.99"#input("Enter server IP address or hostname:")
    username = "admin" #input("Enter username: ")

    if sys.stdin.isatty():
        password = "Aa123456"#getpass.getpass("Enter password: ")
    else:
        print("Attention! Your password will be shown on the screen!")
        password = "Aa123456" #input("Enter password: ")

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:


        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login(username, password)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        show_sessions_res = client.api_query("show-sessions", "full")

        if not show_sessions_res.success:
            print("Failed to retrieve the sessions")
            return

        for sessionObj in show_sessions_res.data:
            # Ignore sessions that were not created with WEB APIs or CLI
            print (type(sessionObj))
            if sessionObj["application"] != "WEB_API":
                continue

            discard_res = client.api_call("discard", {"uid": sessionObj['uid']})
            if discard_res.success:
                print("Session '{}' discarded successfully".format(sessionObj['uid']))
            else:
                print("Session '{}' failed to discard".format(sessionObj['uid']))



if __name__ == "__main__":
    main()
