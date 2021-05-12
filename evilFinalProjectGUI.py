from tkinter import *

window = Tk()  # create tkinter GUI object
window.title("Group 1 Final Project")  # Project Title
window.geometry('560x270')  # Set size of the pane
# GUI Buttons
def buttonMitM():
    outputText.insert(END,"MitM Engaged\n")
def buttonSniffer():
    outputText.insert(END,"Sniffer Engaged\n")
def buttonPacketProcessor():
    outputText.insert(END,"Packet Processor Engaged\n")
def buttonrestoreARP():
    outputText.insert(END,"Restore ARP Engaged\n")


#Label for number of CPU cores
labelNo_Of_CPU = Label(window,text="Number of CPU Cores (2,3,6)")
labelNo_Of_CPU.grid(column=0,row=3)

#Entry field for number of CPU cores
textNo_Of_CPU = Entry(window,width=20)
textNo_Of_CPU.grid(column=1,row=3)

# Label for chosen interface
labelInterface = Label(window, text="Select Interface")
labelInterface.grid(column=0, row=0)

# Text input for chosen interface
textInterface = Entry(window, width=20)
textInterface.grid(column=1, row=0)

# Label for victim IP input
labelVictimIP = Label(window, text="Victim IP")
labelVictimIP.grid(column=0, row=1)

# Text input for victim IP
textVictimIP = Entry(window, width=20)
textVictimIP.grid(column=1, row=1)

# Label for router IP input
labelRouterIP = Label(window, text="Router IP")
labelRouterIP.grid(column=0, row=2)

# Text Input for router IP
textRouterIP = Entry(window, width=20)
textRouterIP.grid(column=1, row=2)

def storeVariables():
    #store the variable textNo_Of_CPU 
    varTextNo_Of_CPU= textNo_Of_CPU.get()
    print(varTextNo_Of_CPU)
    #store the variable textInterface
    varTextInterface = textInterface.get()
    print(varTextInterface)
    #store the variable 
    varTextVictimIP = textVictimIP.get()
    print(varTextVictimIP)
    #store the variable textRouterIP
    varTextRouterIP = textRouterIP.get()
    print(varTextRouterIP)
    outputText.insert(END,"Input Variables Stored!\n")

# Button for handling mitm() execute call
buttonMitM = Button(window, text="MitM", command=buttonMitM)
buttonMitM.grid(column=2, row=0)

# Button for handling sniff_packets() execute call
buttonPacketSniffer = Button(window, text="Engage Packet Sniff", command=buttonSniffer)
buttonPacketSniffer.grid(column=2, row=1)

# button for handling process_packets() call
buttonPacketProcessor = Button(window, text="Engage Packet Processor", command=buttonPacketProcessor)
buttonPacketProcessor.grid(column=2, row=2)

# Button for handling restoreARP() call
buttonRestoreARP = Button(window, text="Restore ARP", command=buttonrestoreARP)
buttonRestoreARP.grid(column=2, row=3)

#Create a button to store the variables
buttonStoreVariables = Button(window, text= "Store Variables", command=storeVariables)
buttonStoreVariables.grid(column=2,row=5)
# Button for closing the application
buttonClose = Button(window, text="Quit",command=exit)
buttonClose.grid(column=1, row=10)

outputText = Text(window,height=5,width=35)
outputText.grid(column=0,row=9)

window.mainloop()  # keeps window open