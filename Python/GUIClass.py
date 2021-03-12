import socket, threading, time, json
from tkinter import *
from tkinter import ttk
from tkinter import messagebox, Checkbutton, IntVar
from PacketSnifferClass import Sniffer
from datetime import datetime
from MailClass import Mailer

class GUI:
    currentCaptureState = False
    index = 0
    time = None
    config = None
    def __init__(self, config):
        GUI.config = config
        self.newWindow = None
        self.AlertShownDOS = 0
        self.AlertShownDDOS = 0
        self.AlertShownFTP = 0
        self.main_window = Tk()
        self.main_window.geometry('+{}+{}'.format(int(self.main_window.winfo_screenwidth()/3 - self.main_window.winfo_reqwidth()/2),
                                                  int(self.main_window.winfo_screenheight()/3 - self.main_window.winfo_reqheight()/2)))
        self.main_window.geometry('750x300')
        self.main_window.title('Intrusion Detection System')
        style = ttk.Style()
        style.map("Treeview")
        self.loadTreeView()
        self.btnStartCapture = Button(self.main_window,text="Capture Packet", width=13, relief=RAISED,
                                      disabledforeground="black", bg='#856ff8', fg='white', font=('helvetica', 9, 'bold'), state=NORMAL,command=self.startCapture)
        self.btnStopCapture = Button(self.main_window,text="Stop Capture", width=13, relief=RAISED,
                                     disabledforeground="black", bg='#856ff8', fg='white', font=('helvetica', 9, 'bold'), state=DISABLED,command=self.stopCapture)
        self.btnConfig = Button(self.main_window,text="Configuration",relief=RAISED, width=13,
                                disabledforeground="black", bg='#856ff8', fg='white', font=('helvetica', 9, 'bold'), state=NORMAL,command=self.configWindow)
        self.btnStartCapture.pack(pady=10)
        self.btnStopCapture.pack(pady=10)
        self.btnConfig.pack(pady=10)
        self.btnStartCapture.place(x=270, y=240)
        self.btnStopCapture.place(x=400, y=240)
        self.btnConfig.place(x=530, y=240)
        self.labelText = StringVar()
        self.label = Label(self.main_window, anchor = CENTER , textvariable = self.labelText,font=('Helvetica', 9, 'bold') ,relief = GROOVE, fg = "blue")
        self.labelText.set(" Number of Packets Captured: {}  ".format(GUI.index))
        self.label.place(x=25, y=243)
        self.main_window.protocol('WM_DELETE_WINDOW',self.onClosing)
        self.main_window.resizable(FALSE,FALSE)
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
        self.scroll_bar = Scrollbar(self.frame,orient=VERTICAL, command=self.tree_view.yview)
        self.scroll_bar.pack(side=RIGHT, fill=Y)
        # Attaching Scrollbar
        self.tree_view.config(yscrollcommand=self.scroll_bar.set)
        # Color for Attack Detection
        self.tree_view.tag_configure('attack', background='red')
        # More Details
        self.tree_view.bind("<Double-1>", self.OnDoubleClick)

    def capturing(self):
        while GUI.currentCaptureState and not self.thread.stopped():
            raw_packet, IPaddr = self.s.recvfrom(65536)
            ps_object = Sniffer(raw_packet, GUI.config, "WIN")
            capture = ps_object.capturePacket()
            if not bool(capture) and capture != None:
                row = ps_object.appendRowToGUI()
                self.appendData(GUI.index, GUI.index+1, row)
                GUI.index = GUI.index + 1
            elif bool(capture):
                row = ps_object.appendRowToGUI()
                self.appendData(GUI.index, GUI.index+1, row, ('attack',))
                if capture[0] == "Distributed Denial of Service":
                    self.alertAttackDDOS(capture)
                if capture[0] == "Denial of Service":
                    self.alertAttackDOS(capture)
                if capture[0] == "FTP Brute Force Attack":
                    self.alertAttackFTP(capture)
                GUI.index = GUI.index + 1
            if GUI.config["logEnabled"] and not bool(capture) and capture != None:
                ps_object.logPacketToFile(GUI.index+1, self.filename)
            elif GUI.config["logEnabled"] and bool(capture):
                ps_object.logPacketToFile(GUI.index+1, self.filename, "AttackPacket")
            try:
                self.labelText.set(" Number of Packets Captured: {}  ".format(GUI.index))
            except:
                pass

    def startCapture(self):
        self.btnStartCapture.config(state=DISABLED)
        self.btnConfig.config(state=DISABLED)
        self.btnStopCapture.config(state=NORMAL)
        GUI.currentCaptureState = True
        # HOST = socket.gethostbyname(socket.gethostname())
        # HOST = socket.gethostbyname(socket.gethostname())
        HOST = socket.gethostbyname_ex(socket.gethostname())[2][0]
        # HOST = "192.168.1.23"
        print("Interface IP: %s" % HOST)
        # Create a raw socket and bind it to the public interface
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.s.bind((HOST, 0))
        # Include IP headers
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Promiscuous mode - Enabled
        self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        if GUI.config["logEnabled"] == True:
            format = "%d_%m_%Y_%H_%M_%S"
            self.filename = datetime.now().strftime(format)+".txt"
            with open('./'+str(self.filename), 'w'):
                pass
        else:
            self.filename = "None.txt"
        if GUI.time == None:
            GUI.time = time.time()
        self.thread = StoppableThread(target=self.capturing, daemon=True)
        self.thread.start()

    def stopCapture(self):
        self.btnStartCapture.config(state=NORMAL)
        self.btnConfig.config(state=NORMAL)
        self.btnStopCapture.config(state=DISABLED)
        GUI.currentCaptureState = False
        self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        self.thread.stop()

    def disableAll(self,mainAttack):
        if mainAttack == "DOS":
            self.dospingcheckbox.config(state=DISABLED)
            self.dossyncheckbox.config(state=DISABLED)
            self.dosudpcheckbox.config(state=DISABLED)
            self.dping_threshold.config(state=DISABLED)
            self.dping_timeinterval.config(state=DISABLED)
            self.dsyn_threshold.config(state=DISABLED)
            self.dsyn_timeinterval.config(state=DISABLED)
            self.dudp_threshold.config(state=DISABLED)
            self.dudp_timeinterval.config(state=DISABLED)
        elif mainAttack == "DDOS":
            self.ddospingcheckbox.config(state=DISABLED)
            self.ddossyncheckbox.config(state=DISABLED)
            self.ddosudpcheckbox.config(state=DISABLED)
            self.ddping_threshold.config(state=DISABLED)
            self.ddping_timeinterval.config(state=DISABLED)
            self.ddsyn_threshold.config(state=DISABLED)
            self.ddsyn_timeinterval.config(state=DISABLED)
            self.ddudp_threshold.config(state=DISABLED)
            self.ddudp_timeinterval.config(state=DISABLED)

    def enableAll(self,mainAttack):
        if mainAttack == "DOS":
            self.dospingcheckbox.config(state=NORMAL)
            self.dossyncheckbox.config(state=NORMAL)
            self.dosudpcheckbox.config(state=NORMAL)
            self.dping_threshold.config(state=NORMAL)
            self.dping_timeinterval.config(state=NORMAL)
            self.dsyn_threshold.config(state=NORMAL)
            self.dsyn_timeinterval.config(state=NORMAL)
            self.dudp_threshold.config(state=NORMAL)
            self.dudp_timeinterval.config(state=NORMAL)
        elif mainAttack == "DDOS":
            self.ddospingcheckbox.config(state=NORMAL)
            self.ddossyncheckbox.config(state=NORMAL)
            self.ddosudpcheckbox.config(state=NORMAL)
            self.ddping_threshold.config(state=NORMAL)
            self.ddping_timeinterval.config(state=NORMAL)
            self.ddsyn_threshold.config(state=NORMAL)
            self.ddsyn_timeinterval.config(state=NORMAL)
            self.ddudp_threshold.config(state=NORMAL)
            self.ddudp_timeinterval.config(state=NORMAL)

    def configWindow(self):
        if self.newWindow == None:
            self.main_window.withdraw()
            self.newWindow = Toplevel(self.main_window)
            self.newWindow.focus_force()
            self.newWindow.geometry('300x350')
            self.newWindow.geometry('+{}+{}'.format(int(self.newWindow.winfo_screenwidth()/2 - self.newWindow.winfo_reqwidth()/2),
                                                      int(self.newWindow.winfo_screenheight()/3 - self.newWindow.winfo_reqheight()/2)))
            self.newWindow.title("Edit Configuration")
            self.newWindow.resizable(FALSE,FALSE)
            Label(self.newWindow, text="Threshold", font=('helvetica', 9, 'underline')).place(x=135,y=12)
            Label(self.newWindow, text="Time Interval", font=('helvetica', 9, 'underline')).place(x=210,y=12)
            self.newWindow.protocol('WM_DELETE_WINDOW',self.configClosed)
            # DOS checkbox
            self.var_dos = IntVar(self.newWindow)
            self.doscheckbox = Checkbutton(self.newWindow, font=('helvetica', 9, 'bold'), text='Denial of Service',variable=self.var_dos, onvalue=1, offvalue=0, command=lambda: self.configAttack("DOS"))
            self.doscheckbox.pack(pady=10)
            self.doscheckbox.place(x=10,y=10)
            # DOS Ping Checkbox & Fields
            self.var_dos_ping = IntVar(self.newWindow)
            self.dospingcheckbox = Checkbutton(self.newWindow, text='Ping Flood',variable=self.var_dos_ping, onvalue=1, offvalue=0, command=lambda: self.configAttack("DOS", "ping"))
            self.dospingcheckbox.pack(pady=10)
            self.dospingcheckbox.place(x=40,y=40)
            self.dping_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.dping_threshold.place(x=140,y=44)
            self.dping_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.dping_timeinterval.place(x=220,y=44)
            # DOS SYN Checkbox & Fields
            self.var_dos_syn = IntVar(self.newWindow)
            self.dossyncheckbox = Checkbutton(self.newWindow, text='SYN Flood',variable=self.var_dos_syn, onvalue=1, offvalue=0, command=lambda: self.configAttack("DOS", "syn"))
            self.dossyncheckbox.pack(pady=10)
            self.dossyncheckbox.place(x=40,y=70)
            self.dsyn_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.dsyn_threshold.place(x=140,y=74)
            self.dsyn_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.dsyn_timeinterval.place(x=220,y=74)
            # DOS UDP Checkbox & Fields
            self.var_dos_udp = IntVar(self.newWindow)
            self.dosudpcheckbox = Checkbutton(self.newWindow, text='UDP Flood',variable=self.var_dos_udp, onvalue=1, offvalue=0, command=lambda: self.configAttack("DOS", "udp"))
            self.dosudpcheckbox.pack(pady=10)
            self.dosudpcheckbox.place(x=40,y=100)
            self.dudp_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.dudp_threshold.place(x=140,y=104)
            self.dudp_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.dudp_timeinterval.place(x=220,y=104)
            self.dping_threshold.insert(END, GUI.config["DOS"]["ping"]["threshold"])
            self.dping_timeinterval.insert(END, GUI.config["DOS"]["ping"]["timeinterval"])
            self.dsyn_threshold.insert(END, GUI.config["DOS"]["syn"]["threshold"])
            self.dsyn_timeinterval.insert(END, GUI.config["DOS"]["syn"]["timeinterval"])
            self.dudp_threshold.insert(END, GUI.config["DOS"]["udp"]["threshold"])
            self.dudp_timeinterval.insert(END, GUI.config["DOS"]["udp"]["timeinterval"])
            if GUI.config["DOS"]["status"] == True:
                self.doscheckbox.select()
                if GUI.config["DOS"]["ping"]["status"] == True:
                    self.dospingcheckbox.select()
                    self.dping_threshold.config(state=NORMAL)
                    self.dping_timeinterval.config(state=NORMAL)
                else:
                    self.dping_threshold.config(state=DISABLED)
                    self.dping_timeinterval.config(state=DISABLED)
                if GUI.config["DOS"]["syn"]["status"] == True:
                    self.dossyncheckbox.select()
                    self.dsyn_threshold.config(state=NORMAL)
                    self.dsyn_timeinterval.config(state=NORMAL)
                else:
                    self.dsyn_threshold.config(state=DISABLED)
                    self.dsyn_timeinterval.config(state=DISABLED)
                if GUI.config["DOS"]["udp"]["status"] == True:
                    self.dosudpcheckbox.select()
                    self.dudp_threshold.config(state=NORMAL)
                    self.dudp_timeinterval.config(state=NORMAL)
                else:
                    self.dudp_threshold.config(state=DISABLED)
                    self.dudp_timeinterval.config(state=DISABLED)
            else:
                self.disableAll("DOS")
            # DDOS checkbox
            self.var_ddos = IntVar(self.newWindow)
            self.ddoscheckbox = Checkbutton(self.newWindow, font=('helvetica', 9, 'bold'), text='Distributed Denial of Service',variable=self.var_ddos, onvalue=1, offvalue=0, command=lambda: self.configAttack("DDOS"))
            self.ddoscheckbox.pack(pady=10)
            self.ddoscheckbox.place(x=10,y=130)
            # DDOS Ping Checkbox & Fields
            self.var_ddos_ping = IntVar(self.newWindow)
            self.ddospingcheckbox = Checkbutton(self.newWindow, text='Ping Flood',variable=self.var_ddos_ping, onvalue=1, offvalue=0, command=lambda: self.configAttack("DDOS", "ping"))
            self.ddospingcheckbox.pack(pady=10)
            self.ddospingcheckbox.place(x=40,y=160)
            self.ddping_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ddping_threshold.place(x=140,y=164)
            self.ddping_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ddping_timeinterval.place(x=220,y=164)
            # DDOS SYN Checkbox & Fields
            self.var_ddos_syn = IntVar(self.newWindow)
            self.ddossyncheckbox = Checkbutton(self.newWindow, text='SYN Flood',variable=self.var_ddos_syn, onvalue=1, offvalue=0, command=lambda: self.configAttack("DDOS", "syn"))
            self.ddossyncheckbox.pack(pady=10)
            self.ddossyncheckbox.place(x=40,y=190)
            self.ddsyn_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ddsyn_threshold.place(x=140,y=194)
            self.ddsyn_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ddsyn_timeinterval.place(x=220,y=194)
            # DDOS UDP Checkbox & Fields
            self.var_ddos_udp = IntVar(self.newWindow)
            self.ddosudpcheckbox = Checkbutton(self.newWindow, text='UDP Flood',variable=self.var_ddos_udp, onvalue=1, offvalue=0, command=lambda: self.configAttack("DDOS", "udp"))
            self.ddosudpcheckbox.pack(pady=10)
            self.ddosudpcheckbox.place(x=40,y=220)
            self.ddudp_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ddudp_threshold.place(x=140,y=224)
            self.ddudp_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ddudp_timeinterval.place(x=220,y=224)
            self.ddping_threshold.insert(END, GUI.config["DDOS"]["ping"]["threshold"])
            self.ddping_timeinterval.insert(END, GUI.config["DDOS"]["ping"]["timeinterval"])
            self.ddsyn_threshold.insert(END, GUI.config["DDOS"]["syn"]["threshold"])
            self.ddsyn_timeinterval.insert(END, GUI.config["DDOS"]["syn"]["timeinterval"])
            self.ddudp_threshold.insert(END, GUI.config["DDOS"]["udp"]["threshold"])
            self.ddudp_timeinterval.insert(END, GUI.config["DDOS"]["udp"]["timeinterval"])
            if GUI.config["DDOS"]["status"] == True:
                self.ddoscheckbox.select()
                if GUI.config["DDOS"]["ping"]["status"] == True:
                    self.ddospingcheckbox.select()
                    self.ddping_threshold.config(state=NORMAL)
                    self.ddping_timeinterval.config(state=NORMAL)
                else:
                    self.ddping_threshold.config(state=DISABLED)
                    self.ddping_timeinterval.config(state=DISABLED)
                if GUI.config["DDOS"]["syn"]["status"] == True:
                    self.ddossyncheckbox.select()
                    self.ddsyn_threshold.config(state=NORMAL)
                    self.ddsyn_timeinterval.config(state=NORMAL)
                else:
                    self.ddsyn_threshold.config(state=DISABLED)
                    self.ddsyn_timeinterval.config(state=DISABLED)
                if GUI.config["DDOS"]["udp"]["status"] == True:
                    self.ddosudpcheckbox.select()
                    self.ddudp_threshold.config(state=NORMAL)
                    self.ddudp_timeinterval.config(state=NORMAL)
                else:
                    self.ddudp_threshold.config(state=DISABLED)
                    self.ddudp_timeinterval.config(state=DISABLED)
            else:
                self.disableAll("DDOS")
            # FTP Brute Force
            self.var_ftp = IntVar(self.newWindow)
            self.ftpcheckbox = Checkbutton(self.newWindow, font=('helvetica', 9, 'bold'), text='FTP Brute Force',variable=self.var_ftp, onvalue=1, offvalue=0, command=self.configFTPAttack)
            self.ftpcheckbox.pack(pady=10)
            self.ftpcheckbox.place(x=10,y=250)
            self.ftp_threshold = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ftp_threshold.place(x=140,y=254)
            self.ftp_timeinterval = Entry(self.newWindow, width=8, relief=GROOVE)
            self.ftp_timeinterval.place(x=220,y=254)
            self.ftp_threshold.insert(END, GUI.config["FTP"]["threshold"])
            self.ftp_timeinterval.insert(END, GUI.config["FTP"]["timeinterval"])
            if GUI.config["FTP"]["status"] == True:
                self.ftpcheckbox.select()
                self.ftp_threshold.config(state=NORMAL)
                self.ftp_timeinterval.config(state=NORMAL)
            else:
                self.ftpcheckbox.deselect()
                self.ftp_threshold.config(state=DISABLED)
                self.ftp_timeinterval.config(state=DISABLED)
            # Packet Log
            self.dumy_var = IntVar(self.newWindow)
            self.checkbox = Checkbutton(self.newWindow, font=('helvetica', 9, 'bold'), text='Log Packets',variable=self.dumy_var, onvalue=1, offvalue=0, command=self.updateLogState)
            self.checkbox.pack(pady=10)
            self.checkbox.place(x=10,y=280)
            if GUI.config["logEnabled"] == True:
                self.checkbox.select()
            self.newWindow.mainloop()

    def configAttack(self, mainAttack, type=None):
        if mainAttack == "DOS" and type == None:
            if self.var_dos.get() == 1:
                GUI.config[mainAttack]["ping"]["status"]=True
                GUI.config[mainAttack]["syn"]["status"]=True
                GUI.config[mainAttack]["udp"]["status"]=True
                self.dospingcheckbox.select()
                self.dossyncheckbox.select()
                self.dosudpcheckbox.select()
                GUI.config[mainAttack]["status"]=True
                self.enableAll("DOS")
            else:
                GUI.config[mainAttack]["ping"]["status"]=False
                GUI.config[mainAttack]["syn"]["status"]=False
                GUI.config[mainAttack]["udp"]["status"]=False
                self.dospingcheckbox.deselect()
                self.dossyncheckbox.deselect()
                self.dosudpcheckbox.deselect()
                GUI.config[mainAttack]["status"]=False
                self.disableAll("DOS")
        elif mainAttack == "DOS" and type == "ping":
            if self.var_dos_ping.get() == 1:
                GUI.config[mainAttack][type]["status"]=True
                self.dping_threshold.config(state=NORMAL)
                self.dping_timeinterval.config(state=NORMAL)
            else:
                GUI.config[mainAttack][type]["status"]=False
                self.dping_threshold.config(state=DISABLED)
                self.dping_timeinterval.config(state=DISABLED)
        elif mainAttack == "DOS" and type == "syn":
            if self.var_dos_syn.get() == 1:
                GUI.config[mainAttack][type]["status"]=True
                self.dsyn_threshold.config(state=NORMAL)
                self.dsyn_timeinterval.config(state=NORMAL)
            else:
                GUI.config[mainAttack][type]["status"]=False
                self.dsyn_threshold.config(state=DISABLED)
                self.dsyn_timeinterval.config(state=DISABLED)
        elif mainAttack == "DOS" and type == "udp":
            if self.var_dos_udp.get() == 1:
                GUI.config[mainAttack][type]["status"]=True
                self.dudp_threshold.config(state=NORMAL)
                self.dudp_timeinterval.config(state=NORMAL)
            else:
                GUI.config[mainAttack][type]["status"]=False
                self.dudp_threshold.config(state=DISABLED)
                self.dudp_timeinterval.config(state=DISABLED)
        elif mainAttack == "DDOS" and type == None:
            if self.var_ddos.get() == 1:
                GUI.config[mainAttack]["ping"]["status"]=True
                GUI.config[mainAttack]["syn"]["status"]=True
                GUI.config[mainAttack]["udp"]["status"]=True
                self.ddospingcheckbox.select()
                self.ddossyncheckbox.select()
                self.ddosudpcheckbox.select()
                GUI.config[mainAttack]["status"]=True
                self.enableAll("DDOS")
            else:
                GUI.config[mainAttack]["ping"]["status"]=False
                GUI.config[mainAttack]["syn"]["status"]=False
                GUI.config[mainAttack]["udp"]["status"]=False
                self.ddospingcheckbox.deselect()
                self.ddossyncheckbox.deselect()
                self.ddosudpcheckbox.deselect()
                GUI.config[mainAttack]["status"]=False
                self.disableAll("DDOS")
        elif mainAttack == "DDOS" and type == "ping":
            if self.var_ddos_ping.get() == 1:
                GUI.config[mainAttack][type]["status"]=True
                self.ddping_threshold.config(state=NORMAL)
                self.ddping_timeinterval.config(state=NORMAL)
            else:
                GUI.config[mainAttack][type]["status"]=False
                self.ddping_threshold.config(state=DISABLED)
                self.ddping_timeinterval.config(state=DISABLED)
        elif mainAttack == "DDOS" and type == "syn":
            if self.var_ddos_syn.get() == 1:
                GUI.config[mainAttack][type]["status"]=True
                self.ddsyn_threshold.config(state=NORMAL)
                self.ddsyn_timeinterval.config(state=NORMAL)
            else:
                GUI.config[mainAttack][type]["status"]=False
                self.ddsyn_threshold.config(state=DISABLED)
                self.ddsyn_timeinterval.config(state=DISABLED)
        elif mainAttack == "DDOS" and type == "udp":
            if self.var_ddos_udp.get() == 1:
                GUI.config[mainAttack][type]["status"]=True
                self.ddudp_threshold.config(state=NORMAL)
                self.ddudp_timeinterval.config(state=NORMAL)
            else:
                GUI.config[mainAttack][type]["status"]=False
                self.ddudp_threshold.config(state=DISABLED)
                self.ddudp_timeinterval.config(state=DISABLED)

    def configFTPAttack(self):
        if self.var_ftp.get() == 1:
            GUI.config["FTP"]["status"]=True
            self.ftpcheckbox.select()
            self.ftp_threshold.config(state=NORMAL)
            self.ftp_timeinterval.config(state=NORMAL)
        else:
            GUI.config["FTP"]["status"]=False
            self.ftpcheckbox.deselect()
            self.ftp_threshold.config(state=DISABLED)
            self.ftp_timeinterval.config(state=DISABLED)

    def configClosed(self):
        try:
            temp = GUI.config
            temp["DOS"]["ping"]["threshold"] = int(self.dping_threshold.get())
            temp["DOS"]["ping"]["timeinterval"] = int(self.dping_timeinterval.get())
            temp["DOS"]["syn"]["threshold"] = int(self.dsyn_threshold.get())
            temp["DOS"]["syn"]["timeinterval"] = int(self.dsyn_timeinterval.get())
            temp["DOS"]["udp"]["threshold"] = int(self.dudp_threshold.get())
            temp["DOS"]["udp"]["timeinterval"] = int(self.dudp_timeinterval.get())
            temp["DDOS"]["ping"]["threshold"] = int(self.ddping_threshold.get())
            temp["DDOS"]["ping"]["timeinterval"] = int(self.ddping_timeinterval.get())
            temp["DDOS"]["syn"]["threshold"] = int(self.ddsyn_threshold.get())
            temp["DDOS"]["syn"]["timeinterval"] = int(self.ddsyn_timeinterval.get())
            temp["DDOS"]["udp"]["threshold"] = int(self.ddudp_threshold.get())
            temp["DDOS"]["udp"]["timeinterval"] = int(self.ddudp_timeinterval.get())
            temp["FTP"]["threshold"] = int(self.ftp_threshold.get())
            temp["FTP"]["timeinterval"] = int(self.ftp_timeinterval.get())
            GUI.config = temp
        except:
            pass
        with open('./Config.json','w') as file:
            json.dump(GUI.config, file)
        self.newWindow.destroy()
        self.main_window.deiconify()
        self.newWindow = None

    def alertAttackDOS(self,display):
        if self.AlertShownDOS == 0:
            mailer = Mailer(GUI.config["Mail"])
            mailer.send("Alert! Denial of Service detected from IP: {}\nType: {} Flood!".format(display[1], display[2].upper()))
            self.alertdos = Tk()
            self.alertdos.title(display[0])
            self.alertdos.geometry("350x50")
            self.alertdos.geometry('+{}+{}'.format(int(self.alertdos.winfo_screenwidth()/2.3 - self.alertdos.winfo_reqwidth()/2),
                                                      int(self.alertdos.winfo_screenheight()/2 - self.alertdos.winfo_reqheight()/2)))
            self.alertdos.winfo_toplevel()
            self.alertdos.focus_force()
            Label(self.alertdos, anchor=CENTER, text="Alert! Denial of Service detected from IP: {}\nType: {} Flood!".format(display[1], display[2].upper()), font=('helvetica', 9)).pack()
            self.alertdos.protocol('WM_DELETE_WINDOW', self.alertdosClosed)
            self.alertdos.mainloop()

    def alertdosClosed(self):
        self.alertdos.destroy()
        self.AlertShownDOS = 1

    def alertAttackDDOS(self,display):
        if self.AlertShownDDOS == 0:
            mailer = Mailer(GUI.config["Mail"])
            mailer.send("Alert! Distributed Denial of Service detected from \nIP's: {}\nType: {} Flood!".format(', '.join(list(display[1])), display[2].upper()))
            self.alertddos = Tk()
            self.alertddos.title(display[0])
            self.alertddos.geometry("400x50")
            self.alertddos.geometry('+{}+{}'.format(int(self.alertddos.winfo_screenwidth()/2.3 - self.alertddos.winfo_reqwidth()/2),
                                                   int(self.alertddos.winfo_screenheight()/2 - self.alertddos.winfo_reqheight()/2)))
            self.alertddos.winfo_toplevel()
            self.alertddos.focus_force()
            Label(self.alertddos, anchor=CENTER, text="Alert! Distributed Denial of Service detected from \nIP's: {}\nType: {} Flood!".format(', '.join(list(display[1])), display[2].upper()), font=('helvetica', 9)).pack()
            self.alertddos.protocol('WM_DELETE_WINDOW', self.alertddosClosed)
            self.alertddos.mainloop()

    def alertddosClosed(self):
        self.alertddos.destroy()
        self.AlertShownDDOS = 1

    def alertAttackFTP(self,display):
        if self.AlertShownFTP == 0:
            mailer = Mailer(GUI.config["Mail"])
            mailer.send("Alert! FTP Login-Brute Force Attack detected from \nIP: {}!".format(display[1]))
            self.alertftp = Tk()
            self.alertftp.title(display[0])
            self.alertftp.geometry("350x50")
            self.alertftp.geometry('+{}+{}'.format(int(self.alertftp.winfo_screenwidth()/2.3 - self.alertftp.winfo_reqwidth()/2),
                                                   int(self.alertftp.winfo_screenheight()/2 - self.alertftp.winfo_reqheight()/2)))
            self.alertftp.winfo_toplevel()
            self.alertftp.focus_force()
            Label(self.alertftp, anchor=CENTER, text="Alert! FTP Login-Brute Force Attack detected from \nIP: {}!".format(display[1]), font=('helvetica', 9)).pack()
            self.alertftp.protocol('WM_DELETE_WINDOW', self.alertftpClosed)
            self.alertftp.mainloop()

    def alertftpClosed(self):
        self.alertftp.destroy()
        self.AlertShownFTP = 1

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
        if selectedPacket["protocol"] == 1:
            TYPE_STR = {8: "Request", 0: "Reply", 3: "Error"}
            message = """Packet ID: {}
Version: {}
Header Length: {} bytes
Time to Live: {} seconds
Protocol: {}
Source IP Address: {}
Destination IP Address: {}
Type: {} - {}
Code: {}
Sequence Number: {}""".format(selectedPacket["pacID"],selectedPacket['version'], selectedPacket['header_length'], selectedPacket['time_to_live'], selectedPacket['protocol'],
                       selectedPacket['src_ip_addr'], selectedPacket['dest_ip_addr'],selectedPacket['type_icmp'], TYPE_STR[selectedPacket['type_icmp']], selectedPacket['code'], selectedPacket['sequence_number'])
        elif selectedPacket["protocol"] == 6:
            message = """Packet ID: {}
Version: {}
Header Length: {} bytes
Time to Live: {} seconds
Protocol: {}
Source IP Address: {}
Destination IP Address: {}
Source Port: {}
Destination Port: {}
Sequence Number: {}
Acknowlegdement Number: {}
Header Length:{} Bytes
URG Flag: {}
ACK Flag: {}
PSH Flag: {}
RST Flag: {}
SYN Flag: {}
FIN Flag: {}""".format(selectedPacket["pacID"],selectedPacket['version'], selectedPacket['header_length'], selectedPacket['time_to_live'], selectedPacket['protocol'],
                       selectedPacket['src_ip_addr'], selectedPacket['dest_ip_addr'],selectedPacket['src_port'], selectedPacket['dest_port'], selectedPacket['seq_number'], selectedPacket['ack_number'],
                       selectedPacket['header_length_tcp'], selectedPacket['URG_Flag'], selectedPacket['ACK_Flag'], selectedPacket['PSH_Flag'],
                       selectedPacket['RST_Flag'], selectedPacket['SYN_Flag'], selectedPacket['FIN_Flag'])
        elif selectedPacket["protocol"] == 17:
            message = """Packet ID: {}
Version: {}
Header Length: {} bytes
Time to Live: {} seconds
Protocol: {}
Source IP Address: {}
Destination IP Address: {}
Source Port: {}
Destination Port: {}
Data Length:{} Bits""".format(selectedPacket["pacID"],selectedPacket['version'], selectedPacket['header_length'], selectedPacket['time_to_live'], selectedPacket['protocol'],
                       selectedPacket['src_ip_addr'], selectedPacket['dest_ip_addr'],selectedPacket['src_port'], selectedPacket['dest_port'], selectedPacket['UDP_len'])
        else:
            message = "None"
        messagebox.showinfo("Selected Packet",message)

    def updateLogState(self):
        if self.dumy_var.get() == 1:
            GUI.config["logEnabled"]=True
        else:
            GUI.config["logEnabled"]=False

    def onClosing(self):
        self.main_window.withdraw()
        sys.exit(0)
        # self.main_window.destroy()

class StoppableThread(threading.Thread):

    def __init__(self, *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def unstop(self):
        self._stop_event.clear()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()