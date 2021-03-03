import socket, threading, time, json
from tkinter import *
from tkinter import ttk
from tkinter import messagebox, Checkbutton, IntVar
from PacketSnifferClass import Sniffer

class GUI:
    currentCaptureState = False
    index = 0
    time = None
    config = None
    def __init__(self, config):
        GUI.config = config
        self.main_window = Tk()
        self.main_window.geometry('750x300')
        self.main_window.title('Intrusion Detection System')
        style = ttk.Style()
        style.map("Treeview")
        self.loadTreeView()
        self.btnStartCapture = Button(self.main_window,text="Capture Packet",relief=RAISED,
                                      state=NORMAL,command=self.startCapture)
        self.btnStopCapture = Button(self.main_window,text="Stop Capture",relief=RAISED,
                                      state=DISABLED,command=self.stopCapture)
        self.btnStartCapture.pack(pady=10)
        self.btnStopCapture.pack(pady=10)
        self.btnStartCapture.place(x=270, y=230)
        self.btnStopCapture.place(x=380, y=230)
        # self.btnStopCapture.place(x=150,y=100)
        self.dumy_var = IntVar(self.main_window)
        self.checkbox = Checkbutton(self.main_window, text='Log Packets',variable=self.dumy_var, onvalue=1, offvalue=0, command=self.updateLogState)
        self.checkbox.pack(pady=10)
        self.checkbox.place(x=20, y=230)
        if GUI.config["logEnabled"] == True:
            self.checkbox.select()
        self.main_window.protocol('WM_DELETE_WINDOW',self.onClosing)
        self.main_window.mainloop()

    def loadTreeView(self):
        self.frame = Frame(self.main_window)
        self.frame.pack(pady=20)
        self.tree_view = ttk.Treeview(self.frame, columns=('id','time','src_ip', 'dst_ip', 'proto', 'info')
                                      ,show='headings', height=8, selectmode="browse")
        self.tree_view.pack(side=LEFT)
        # Treeview Column Config
        self.tree_view.column('id', anchor=CENTER, width=50)
        self.tree_view.column('time', anchor=CENTER, width= 80)
        # self.tree_view.column('src_mac', anchor=CENTER, width= 140)
        # self.tree_view.column('dst_mac', anchor=CENTER, width = 140)
        self.tree_view.column('src_ip', anchor=CENTER, width = 140)
        self.tree_view.column('dst_ip', anchor=CENTER, width = 140)
        self.tree_view.column('proto', anchor=CENTER, width=70)
        self.tree_view.column('info', anchor=CENTER)
        # Heading
        self.tree_view.heading('id', text='ID')
        self.tree_view.heading('time', text='Time')
        self.tree_view.heading('src_ip', text='Source IP')
        self.tree_view.heading('dst_ip', text='Destination IP')
        self.tree_view.heading('proto', text='Protocol')
        self.tree_view.heading('info', text='Info')
        # Scrollbar
        self.scroll_bar = Scrollbar(self.frame,orient=VERTICAL)
        self.scroll_bar.pack(side=RIGHT, fill=Y)
        # Attaching Scrollbar
        self.tree_view.config(yscrollcommand=self.scroll_bar.set)
        self.scroll_bar.config(command=self.tree_view.yview())
        # Color for Attack Detection
        self.tree_view.tag_configure('attack', background='red')
        # More Details
        self.tree_view.bind("<Double-1>", self.OnDoubleClick)

    def capturing(self):
        while True:
            if GUI.currentCaptureState:
                raw_packet, IPaddr = self.s.recvfrom(65536)
                ps_object = Sniffer(raw_packet, GUI.config, "WIN")
                capture = ps_object.capturePacket()
                if capture == 0 or capture == 3:
                    row = ps_object.appendRowToGUI()
                    if capture == 0:
                        self.appendData(GUI.index, GUI.index+1, row)
                    elif capture == 3:
                        self.appendData(GUI.index, GUI.index, row, ('attack',))
                    if GUI.config["logEnabled"]:
                        ps_object.logPacketToFile(GUI.index+1)
                    GUI.index = GUI.index + 1
            else:
                break

    def startCapture(self):
        self.btnStartCapture.config(state=DISABLED)
        self.btnStopCapture.config(state=NORMAL)
        GUI.currentCaptureState = True
        HOST = socket.gethostbyname(socket.gethostname())
        print("Interface IP: %s" % HOST)
        # Create a raw socket and bind it to the public interface
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.s.bind((HOST, 0))
        # Include IP headers
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Promiscuous mode - Enabled
        self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        if GUI.time == None:
            GUI.time = time.time()
        self.thread = threading.Thread(target=self.capturing)
        self.thread.start()

    def stopCapture(self):
        self.btnStartCapture.config(state=NORMAL)
        self.btnStopCapture.config(state=DISABLED)
        GUI.currentCaptureState = False
        self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def appendData(self, currentIndex, currentID, value_list, tags=()):
        try:
            value_list.insert(1,"{:.4f}".format(time.time()-GUI.time))
            self.tree_view.insert(parent='', index=currentIndex, iid=currentID, values=value_list, tags=tags)
        except:
            pass

    def OnDoubleClick(self, event):
        item_selected = self.tree_view.identify('item',event.x,event.y)
        selectedID = int(self.tree_view.item(item_selected,"values")[0])
        with open("./PacketLog.json",'r') as file:
            storedData = json.load(file)
        selectedPacket = [x for x in storedData["Packets"] if x["pacID"]==selectedID][0]
        messagebox.showinfo("Selected Packet",selectedPacket)

    def updateLogState(self):
        if self.dumy_var.get() == 1:
            GUI.config["logEnabled"]=True
        else:
            GUI.config["logEnabled"]=False

    def onClosing(self):
        with open('./Config.json','w') as file:
            json.dump(GUI.config, file)
        self.main_window.destroy()