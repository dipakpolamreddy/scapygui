from Tkinter import *
import Tkinter
import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP,TCP,UDP
from io import BytesIO  
import StringIO
from contextlib import contextmanager
import threading
from ScrolledText import *



root=Tk()
root.title("SCAPY GUI")
root.geometry("800x200")  
topframe=Frame(root)
topframe.pack()
bottomframe=Frame(root) 
bottomframe.pack(side='bottom')
data1=StringVar()
data2=StringVar()
data3=StringVar()
data4=StringVar()
#data entry
label_1=Label(topframe, text="source")
label_2=Label(topframe, text="destination")
label_3=Label(topframe, text="port")
label_4=Label(topframe, text="message")
entry_1=Entry(topframe,textvariable=data1)
entry_2=Entry(topframe,textvariable=data2)
entry_3=Entry(topframe,textvariable=data3)
entry_4=Entry(topframe,textvariable=data4)
label_1.grid(row=0)
label_2.grid(row=1)
label_3.grid(row=2)
label_4.grid(row=3)
entry_1.grid(row=0,column=1)
entry_2.grid(row=1,column=1)
entry_3.grid(row=2,column=1)
entry_4.grid(row=3,column=1)



#drop down box


choice={'ICMP','ARP','TCP','UDP','HTTP'}
Tkvar=StringVar(root)
Tkvar.set('ICMP')
popupMenu=OptionMenu(bottomframe,Tkvar,*choice)
Label(bottomframe,text="type of packet").grid(row=0,column=0)
popupMenu.grid(row=0,column=1)
packetType=''
def change_dropdown(*args):
    if Tkvar.get()=='ICMP':
       global packetType
       packetType='ICMP'
    elif Tkvar.get()=='TCP':
       global packetType
       packetType='TCP'
    elif Tkvar.get()=='UDP':
       global packetType
       packetType='UDP'
    
        

Tkvar.trace('w',change_dropdown)
#to send packet
e=''
d=''
def sendPacket():
    global packetType
    c=data3.get()
    d=data4.get()
    p=''
    
    if  packetType=='ICMP':  
        a=data1.get()
        b=data2.get()
        c=data3.get()
        d=data4.get()
        p=(IP(src=a,dst=b)/ICMP()/d)
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            p.show()
            output = sys.stdout.getvalue()  # retrieve written string
           
            output2= hexdump(p,dump=True)

        finally:
            sys.stdout = old_stdout
        send(p)

        
    elif packetType=='TCP':
        a=data1.get()
        b=data2.get()
        p=(IP(src=a,dst=b)/TCP()/d)
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            p.show()
            output = sys.stdout.getvalue() 
            
            output2= hexdump(p,dump=True)
             # retrieve written string
        finally:
            sys.stdout = old_stdout
        send(p)
          
    elif packetType=='UDP':
        a=data1.get()
        b=data2.get()
        p=(IP(src=a,dst=b)/UDP()/d)
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            p.show()
            output = sys.stdout.getvalue() # retrieve written string
             
            output2= hexdump(p,dump=True)
            
        finally:
            sys.stdout = old_stdout
        send(p)
    
    p.show()
    global e
    global d
    e = output
    d= output2
T = Text(root, height=40, width=30)
T.pack()
def printSomething():
    
    global e
    global d
    print e
    print d    
    
    T.delete('1.0', Tkinter.END)
    T.insert(Tkinter.END, e)
    T.insert(Tkinter.END, d)


    #elif packetType=='ARP':
        #a=data1.get()
        #b=data2.get()
        #op=2
        #p=IP(src=a,dst=b,op)/TCP()
        #send(p)    

button1=Tkinter.Button(bottomframe,text="send packet",command=sendPacket)
button1.grid(row=1,column=0)

button2=Tkinter.Button(bottomframe, text="Print Me", command=printSomething)
button2.grid(row=2,column=0) 


#sniff the data 

T1 = ScrolledText(bottomframe, height=40, width=70)
T1.grid(row=3,column=2)


#def printToBox():
#    with open('sniff.txt','r') as fp:
#        msg=fp.read()
#        fp.close()
#    T1.insert(END,msg)
    


def sniffPackets(packet):        # custom custom packet sniffer action method
    
        if packet.haslayer(IP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            pckt_ttl=packet[IP].ttl
            old_stdout, sys.stdout = sys.stdout, BytesIO()
            try:
                print 'IP Packet: %s is going to %s and has ttl value %s' % (pckt_src,pckt_dst,pckt_ttl)
                output = sys.stdout.getvalue()  # retrieve written string
            finally:
                sys.stdout = old_stdout
            
            print ('IP Packet: %s is going to %s and has ttl value %s' % (pckt_src,pckt_dst,pckt_ttl))
            s='IP Packet: %s is going to %s and has ttl value %s' % (pckt_src,pckt_dst,pckt_ttl)
            T1.insert(END,s+'\n')
thread=None
switch=False
def stopSniffing():
    global switch
    return switch
        
def startSniffing():
    print ('custom packet sniffer')
    sniff(filter="ip",prn=sniffPackets)  
def startSniffBtn():
    global switch
    global thread

    if (thread is None) or (not thread.is_alive()):
        switch=False
        thread=threading.Thread(target=startSniffing)
        thread.start()
def stopSniffBtn():
    global switch
    switch=True
    global thread
    thread.stop()

     
button2=Tkinter.Button(bottomframe, text="sniff the data ", command=startSniffBtn)
button2.grid(row=2,column=0)
button3=Tkinter.Button(bottomframe, text="stop sniff the data ", command=stopSniffBtn)
button3.grid(row=2,column=3)

root.mainloop()
