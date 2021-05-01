import os, configparser, sys, time
from tkinter import *
import hashlib
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

#crack hashed passwords from packet and compare it to the most common passwords
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