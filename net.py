from tkinter import *
import nmap as scanner
import time
import tkinter.font as font



global scanner

scanner=scanner.PortScanner()
root= Tk()
root.title("Network Scanner")
root.configure(bg='black')
root.geometry("600x800")

rootfont = font.Font(size=22)




#_______________________________________________________________________________________________
#Functionality

class Scanner():
    def __init__(self, ip):
        self.ip=ip
    def comprehensive_scan(self):
        scanner.scan(self.ip, '1-500', '-v -sS -sV -sC -A -O')
        ip_stat = scanner[self.ip].state()
        list1.insert(END, "IP Status: {}".format(ip_stat))
        hostname = scanner[self.ip].hostname()
        list1.insert(END, "HostName is {}".format(hostname))
        protos =scanner[self.ip].all_protocols()
        list1.insert(END, "Protocols: {}".format(protos))
        dictkeys = []
        try:
            for i in scanner[self.ip]['tcp'].keys():
                dictkeys.append(i)
            list1.insert(END, "open ports {}".format(dictkeys))
        except:
            list1.insert(END, "No TCP error. Host probably not up")
    def syn_ack(self):
        scanner.scan(self.ip, '1-248', '-v -sS')
        ip_stat = scanner[self.ip].state()
        list1.insert(END, "IP Status: {}".format(ip_stat))
        protos =scanner[self.ip].all_protocols()
        list1.insert(END, "Protocols: {}".format(protos))
        openPorts = scanner[self.ip]['tcp'].keys()
        openport_list = []
        try:
            for i in openPorts:
                openport_list.append(i)
            list1.insert(END, "open ports {}".format(openport_list))
        except:
            list1.insert(END, "No TCP error. Host probably not up")
    def network_hosts_scan(self):
        scanner.scan(hosts=self.ip, arguments="-sn")
        host_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host, status in host_list:
            list1.insert(END, "Host\t {}, {}".format(host, status))
        



def get_info():
    list1.delete(0, END)
    

    ip_address = IpAddress.get()
    if ip_address=="" or ip_address is None:
        list1.insert(END, "Enter a valid IP address")
    else:
        list1.insert(END, "Scanning {}, please wait".format(ip_address))
        scan_type = scanType.get()
        scan_typeText = scan_type
        scannerVersion = "Nmap version:{}".format(scanner.nmap_version())
        list1.insert(END, scannerVersion)
        scan_object = Scanner(ip_address)
    
        time.sleep(1)
        if scan_type=="SYN ACK Scan":
            scan_object.syn_ack()
        elif scan_type=="Comprehensive Scan":
            scan_object.comprehensive_scan()
        else:
            print("here")
            ip_range = ""
            periodCounter=0
            for i in ip_address:
                if i == '.':
                    periodCounter+=1
                    ip_range += i

                else:
                    ip_range += i
                if periodCounter==3:
                    ip_range +="1/24"
                    break
            rangeScan = Scanner(ip_range)
            list1.insert(END, ip_range)
            rangeScan.network_hosts_scan()











#Labels
#_________________________________________________________________________________________________
IPLabel = Label(root, text="Enter an IP address or range", font="Helvectica", bg='black', fg='green', width="30", height=2 )
IPLabel.grid(row=1, column=0, padx=(0, 100), pady=(10))

scanLabel = Label(root, text="Choose Scan Type", font="Helvectica", bg='black', fg='green', width="30", height=2)
scanLabel.grid(row=2, column=0, padx=(0, 100), pady=(10))


#_______________________________________________________________________________________
#inputs
IpAddress= Entry(root, width=30, bg='gray75', fg='green')
IpAddress.grid(row=1, column=1, pady=(10, 10))

scanList = {"SYN ACK Scan", "Comprehensive Scan", "All hosts on Network"}


scanType = StringVar(root)
scanType.set("SYN ACK Scan")
scanTypeMenu = OptionMenu(root, scanType, *scanList)
scanTypeMenu.config(width=30)
scanTypeMenu.config(anchor=CENTER, bg="gray50")
scanTypeMenu.config(height=2)

scanTypeMenu.grid(row=2, column=1, sticky="w")

#_______________________________________________________________________________________
#Button/ TextBox



enterButton = Button(root, text="Initiate Scan", width=30, height=2, command=get_info, anchor=CENTER, bg='black', fg='green')
enterButton.grid(row=3, column=0, pady=(20), sticky='w')

quitButton = Button(root, text="Quit", width=30, command=root.quit, anchor=CENTER, height=2, bg='black', fg='green')
quitButton.grid(row=10, column=1, sticky="w")

# function to change properties of button on hover
def changeOnHover(button, colorOnHover, colorOnLeave):
  
    # adjusting backgroung of the widget
    # background on entering widget
    button.bind("<Enter>", func=lambda e: button.config(
        background=colorOnHover,
        fg='white'
        ))
  
    # background color on leving widget
    button.bind("<Leave>", func=lambda e: button.config(
        background=colorOnLeave))
changeOnHover(quitButton, "blue", "black")
changeOnHover(enterButton, "blue", "black")


list1 = Listbox(root, height=15, width=90)
list1.grid(row=4, column=0, rowspan=5, columnspan=10, pady=(20))

root.mainloop()




