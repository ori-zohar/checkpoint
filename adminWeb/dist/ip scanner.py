__author__ = 's8498053'
import socket
from datetime import datetime
net_activ =input("enter the ip address -")
net_activ1 =net_activ.split('.')
test = ['.']

net_activ_test =net_activ1[0] + test +net_activ1[1] + net_activ1[2] + test
stn1 =int(raw_input("enter the first numbur-"))
edn1 =int(raw_input("enter the last numbur-"))
edn1 =edn1 + 1
td1 =datetime.now()
def scan(addres):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((addres,135))
    if result == 0 :
        return 1
    else:
        return 0

def run():
    for ip in range(stn1,edn1):
        addres =net_activ_test + str (ip)
        if (scan(addres)):
            print("this address is live ")

run()

td2 =datetime.now()
total = td1 +td2
print( "ip address scunning complete in", total)