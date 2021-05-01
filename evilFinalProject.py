import os, configparser, sys, time
from tkinter import *
import hashlib
import time
import multiprocessing
import math
# from scapy.all import *
#Ethical Hacking Python Application

#function declarations




#MitM Section








#Packet Sniff





#if packet is successful, get hash as a string and compare it to dictionary

#create hashes for most common passwords
#dictionary files
english_password_list = "10k_most_common.txt" #input file name
hashed_words_file = "10k_most_common_hashed.txt" #output file name
#hash type
hash_type="md5"

#create hashed version of passwords most common passwords
def create_hash_md5_text_file(input_list, output_file_name, hash_type):
        input_list = list(map(str.strip, input_list)) #strips away the /n
        hashesToExport = []

        # foreach word in the file look for the hash types
        for word in input_list:
            if hash_type == "md5":
                crypt = hashlib.md5()
            elif hash_type == "sha1":
                crypt = hashlib.sha1() 
            crypt.update(bytes(word, encoding='utf-8'))
            hashOfWord = crypt.hexdigest()
            
            hashesToExport.append(hashOfWord)
        print("Creating hash text file: {} ...".format(output_file_name))

        #create output file
        with open(output_file_name, 'w') as f:
            for hashOfWord in hashesToExport:
                f.write("%s/n" % hashOfWord)
        print("{} has been successfully created".format(output_file_name))

#get the list of words from the file
def list_of_words_from_file(filename):
        print("Opening file: {}".format(filename))
        list_of_words = open(filename, 'r', errors='ignore').readlines()
        print("Stripping breaklines from file: {}".format(filename))
        list_of_words = list(map(str.strip, list_of_words))
        return(list_of_words)

#get words from the file
words = list_of_words_from_file(english_password_list)
#create hash
create_hash_md5_text_file(words, hashed_words_file, hash_type)

#END create hash for common passowords

#START crack passwords
def chunks(LIST, NUMBER_OF_PARTS):
    # For item i in a range that is a length of l,
    for i in range(0, len(LIST), NUMBER_OF_PARTS):
        # Create an index range for l of n items:
        yield LIST[i:i+NUMBER_OF_PARTS]

passwords_from_packet = 'passwords_from_packet.txt'

no_of_cpu = multiprocessing.cpu_count()

start = time.perf_counter()

# OPEN HASHED PASSWORD FILE
print("Opening file {} ".format(hashed_words_file))
hashed_password_list = open(passwords_from_packet, 'r').readlines()
hashed_password_list = list(map(str.strip, hashed_password_list)) # strips away breaklines
finish = time.perf_counter()

# OPEN PASSWORDS OBTAINED FROM FROM THE PACKET
print("Opening file {}".format(passwords_from_packet))
hashed_words_list = open(passwords_from_packet, 'r').readlines()
hashed_words_list = list(map(str.strip, hashed_words_list))
finish = time.perf_counter()

# SPLIT HASHED PASSWORD FILE
print("This computer has {0} CPU's, starting splitting of passwords into {0} parts".format(no_of_cpu))
no_of_elements_in_sublist = math.ceil(len(hashed_password_list)/no_of_cpu)
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
            print("CPU {}: {}/{} password has been cracked. {} minutes elapsed.".format(cpu_number, number_of_cracked_passwords, len(hashed_password_list), round(finish-start)/60,2)))

# executing codes with multiple cores cpus

if no_of_cpu == 2:
    p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_list[0],"1"])
    p2 = multiprocessing.process(targer=crack, args=[chunks_of_password_list[0],"1"])
    
    p1.start()
    p2.start()

    p1.join()
    p2.join()
    print("Cracking has been completed")

elif no_of_cpu == 4:
    p1 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[0],"1"])
	p2 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[1],"2"])
	p3 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[2],"3"])
	p4 = multiprocessing.Process(target=crack, args=[chunks_of_password_lists[3],"4"])

    p1.start()
	p2.start()
	p3.start()
	p4.start()

	p1.join() # waits until the process is completed
	p2.join()
	p3.join()
	p4.join()
	print("Cracking has been completed")

else: 
    print("Error message: You have {} CPU. This code has been constructed for either 2 or 4 CPU.".format(no_of_cpu))
	print("How to fix: Go to line 52-77. I have hardcoded the number of processors to run this. You'll just have to change the if-else statement to cater to your number of cpu.")



#GUI Rigging
window =Tk() #create tkinter GUI object
window.title("Group 1 Final Project")#Project Title
window.geometry('300x200')#Set size of the pane

#Elements of the GUI

#Label for chosen interface
labelInterface = Label(window,text="Select Interface")
labelInterface.grid(column=0,row=0)

#Text input for chosen interface
textInterface = Entry(window,width=20)
textInterface.grid(column=1,row=0)

#Label for victim IP input
labelVictimIP = Label(window,text="Victim IP")
labelVictimIP.grid(column=0,row=2)

#Text input for victim IP
textVictimIP = Entry(window,width=20)
textVictimIP.grid(column=1,row=2)

#Label for router IP input
labelRouterIP = Label(window,text="Router IP")
labelRouterIP.grid(column=0,row=3)


#Text Input for router IP
textRouterIP = Entry(window,width=20)
textRouterIP.grid(column=1,row=3)

#Button for handling execute call
buttonHack = Button(window,text="Hack!",command="confirm")
buttonHack.grid(column=0, rows=4)

#Button for closing the application
buttonClose= Button(window,text="Quit",command="close")
buttonClose.grid(column=1,row=4)
window.mainloop()#keeps window open