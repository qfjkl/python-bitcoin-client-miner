# -*- coding: utf-8 -*

import socket
from threading import Condition, Thread, Timer, Event
from multiprocessing import Manager
import os
import json
import time
from hashlib import sha256
import codecs
import struct
import pickle
import platform
from libs.Serialize import *
#from numba.core.errors import VerificationError
from tqdm import tqdm
# from numba.experimental import jitclass
import requests
import winreg as reg



# @jitclass
class repeatTimer(Timer):

    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)


# username = os.getlogin()
# folder = os.getcwd()+'/Conf-Files/readBeforeInstall.txt'
# pth = f'C:/Users/{username}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup\n'

# with open(folder, 'w') as file:
    
#     file.write('########################################################################################################################################\n')
#     file.write('#################################################### Please read before using the program ##############################################\n')
#     file.write('- Thanks to copy the folder of this programm in this directorie\n')
#     file.write(pth)
#     file.write('- finally launch the program\n')

class CLIENT():

    def __init__(self):

        self.state = True
        self.part = 100_000
        path = ''
        self.newBlockHasBeenSend = False
        self.threadList=list()
        self.work = None

        # Doc


        if platform.system() == 'Windows':
            path = "\Conf-Files\config.json"
            self.clearConsCmd = 'cls'
        else:
            path = "/Conf-Files/config.json"
            self.clearConsCmd = 'clear screan'

        with open(os.getcwd()+path, "r") as file:
            
            config = file.read()

        self.config = json.loads(config)
        try:
            publicIp = requests.get('https://api.ipify.org').text

            if(publicIp == self.config['remote-server-host']):
                
                self.host = self.config['server-host']
                self.port = self.config['server-port']

            else:
                self.host = self.config['server-host']
                self.port = self.config['server-port']
        except:
            print("[Internet connection Error]".upper())
            self.host = self.config['server-host']
            self.port = self.config['server-port']
            pass


    def launchProgramAtTheStartup(self):

        path = os.path.dirname(os.path.realpath(__file__))
        address = os.path.join(path, 'MSN-CLIENT.exe')
        keyValue = 'Software\Microsoft\Windows\CurrentVersion\Run'
        value_name = 'MSN-CLIENT'
        
        with reg.OpenKey(reg.HKEY_CURRENT_USER, keyValue, 0, reg.KEY_ALL_ACCESS) as open:
        
            try:
                reg.QueryValueEx(open, value_name)
                # username = os.getlogin()
                # folder = os.getcwd()+'/readBeforeInstall.txt'
                # pth = f'" C:/Users/{username}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"'
                # with open(folder, 'w') as file:
                #     file.write('########################################################################################################################################')
                #     file.write('#################################################### Please read before using the program ##############################################')
                #     file.write('- Thanks to copy the folder of this programm in this directorie')
                #     file.write(pth)
                #     file.write('- finally launch the program')

            except FileNotFoundError:
                reg.SetValueEx(open, value_name, 0, reg.REG_SZ, address)
                # reg.CloseKey(open)


    def sendStatuOfWorkToServer(self):

        data = {
            'type': 3,
            'rest_of_work': [self.nonce, self.Max]
        }
        if self.connect:
            try:
                # print("[send status of work]")
                self.client.send(pickle.dumps([data]))
            except:
                # self.connect = False
                pass



    def recieve(self):
        
        if self.finishedWork:
            # if 1 == 1:
            try:
                # print("[Trying to recieve new work]".upper())
                recv = self.client.recv(2048)
                if recv != b'0' and recv != b'00':
                    # print('[WE HAVE RECIEVE NEW WORK]')
                    self.newBlockHasBeenSend = True
                    self.work = pickle.loads(recv)

            except ConnectionResetError:
                print('[ERROR OCCURED WHEN WE ARE TRYING TO RECIEVE NEW WORK FROM THE SERVER.]')
                self.connect = False
                pass

            except:
                pass

    def stopThread(self):
        # stop all timer thread
        for _ in self.threadList:
            _.cancel()

    def SearchOfGoodNonce(self, min_nonce, max_nonce, header, target, desc):
        
        # version = header[0]["version"]
        # prevBlockId= header[0]["prevBlock"]
        # merkleRoot = header[0]["merkleRoot"]
        # Time = header[0]["creationTime"]
        # bits = header[0]["bits"]

        # self.Min, self.Max = min_nonce, max_nonce

        # if self.Min > self.Max:
        #     self.Max = self.Min
        #     self.Min = max_nonce

        # self.finishedWork = False
        # self.nonce = self.Min
        # if self.Max>2**32 or self.Min>2**32:
        #     return False                    
        
        msg = f' (Range of Work : [{self.minNonce}; {self.maxNonce}])'.upper()
        if(self.minNonce < self.maxNonce and self.maxNonce <= 2**32):
            for nonce in tqdm(range(self.minNonce, self.maxNonce), desc=desc+msg):
                        
                hash = self.HashHeader(self.version, self.prevBlock, self.merkleRoot, self.creationtTime, self.bits, nonce)
                
                if(hash < target):
                    print("We have found good value")
                    self.nonce = nonce
                    return True
            
        return False


    def HashHeader(self, version, prevBlockId, merkleRoot, time, bits, nonce=None):
       
        header = (struct.pack("<L", version)+
                                codecs.decode(prevBlockId, 'hex')[::-1]
                                +codecs.decode(merkleRoot, 'hex')[::-1]
                                +struct.pack("<L", time)
                                +struct.pack("<L", bits)
                                +struct.pack("<L", nonce)
                            )
           
        digest = sha256(header).digest()
        digest1 = sha256(digest).digest()[::-1]
        Hash = str(codecs.encode(digest1, 'hex'))[2: -1]
        return int(Hash, 16)


    def evalute(self):

        # >
        begin = time.perf_counter()
        target = '000000000000000000001ff2ef9f6a1af873fcf4b7a516f0370d167804be6539'
        header = [
            {
                "version" : 536870916,
                "prevBlock" : "000000000000000000021ff2ef9f6a1af873fcf4b7a516f0370d167804be6539",
                "merkleRoot" : "2ae91caab0cead4fc2045ec0b7532d4386bfce557af73096215ac084ae60ac84",
                "creationTime" : 1625498040,
                "bits" : 0x171398ce,
                "nonce" : 2020207406
            }
        ]

        Min, Max = (1_000_000, 2_000_000)
        
        self.SearchOfGoodNonce(Min, Max, header, self.GetTarget('171398ce'), desc='[EVALUATION TEST]')
        # self.miner(Min, Max, header, target)

        end = time.perf_counter()
        hps = (end -begin)


        return hps

    def deserializeDataForClient(self, raw):

        self.version, raw = deserializeUint32(raw)
        self.prevBlock, raw= deserializeString(raw, 32)
        self.merkleRoot, raw = deserializeString(raw, 32)
        self.creationtTime, raw = deserializeUint32(raw)
        self.bits, raw = deserializeUint32(raw)
        self.target, raw = deserializeString(raw, 32)
        self.minNonce, raw = deserializeUint32(raw)
        self.maxNonce, raw = deserializeUint32(raw)
 
 
        return raw

    
    def sending(self, data):

        # self.client.send(typeOfMsg.encode())
        self.client.send(pickle.dumps(data))

    def GetTarget(self, hexa):
        ##
        ## Compute the target with the target bits notation
        ##
        
        exposant = hexa[:2]
        coeff = hexa[2:]
        cible = int(coeff, 16) * 2 ** (8 * (int(exposant, 16) - 3))
        return  cible


    def connect_to_server(self):
        
        ##
        ## set connection to the server even if one exception happens
        ##
        self.connect = False
        hps = 0
        cpt = 1
        while True:
            self.client = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)

            try:
                self.client.connect((self.host, int(self.port)))
                self.connect = True
                hps = self.evalute()
                
            except TimeoutError:
                if cpt == 1:
                    print('[The server is not available.]'.upper())                
                # os.system(self.clearConsCmd)                
                pass

            except ConnectionRefusedError:
                if cpt == 1:
                    print("[Please wait a moment we are performing maintenance actions on the server.]".upper())
                # os.system(self.clearConsCmd)                
                pass

            except AttributeError:
                if cpt == 1:
                    print('[Internal server error.]'.upper())
                pass

            except:
                if cpt == 1:
                    print("[Unknow error occured]".upper())
                pass
                        
            data = [{
                "type": 0,
                "hps": hps
            }]
            # with Manager() as manager:
            if self.connect:
                try:
                # if 1 == 1:
                    self.client.send(pickle.dumps(data))

                    while True:

                        if(1 == 1):

                            data_receive = self.client.recv(2048)
                            while(data_receive == b'0'):
                                data_receive = self.client.recv(2048)
                            
                            # data_receive = pickle.loads(data_receive)
                            
                            header = [data_receive]
                            target = self.GetTarget(hex(data_receive['bits'])[2:])
                            self.deserializeDataForClient(data_receive)
                            
                            resultOfMining= self.SearchOfGoodNonce(min_nonce = data_receive['min_nonce'],
                                                                    max_nonce = data_receive['max_nonce'],
                                                                    header = header,
                                                                    target = target,
                                                                    desc='[RESEARCH STARTED]')
                            if(resultOfMining):
                            
                                header[0]['nonce'] = self.nonce
                                header[0]['type'] = 1
                                header[0]['hps'] = hps
                                self.client.send(pickle.dumps(header))
                            else:
                                header[0]['type'] = 2
                                header[0]['hps'] = hps
                                header[0]['work'] = [self.Min, self.Max]
                                self.client.send(pickle.dumps(header))

                except BrokenPipeError:
                    if cpt == 1:
                        print('[Broken pipe] connection has been reset by the server please wait a few moment'.upper())
                    pass

                except OSError:
                    if cpt == 1:
                        print("[OS Errors]".upper())
                    pass

                except ConnectionResetError:
                    if cpt == 1:
                        print('[Errno 54] Connection reset by peer'.upper())
                        print('Attempting new connection'.upper())

                        os.system(self.clearConsCmd)
                    pass

                except:
                    if cpt == 1:
                        print("[UNKNOW ERROR OCCURED, PLEASE A MOMENT WE ARE TRYING TO SOLVE THE PROBLEM]")
                    pass

            cpt += 1
            
        self.client.close()





        

if __name__ == '__main__':

    client = CLIENT()

    # client.launchProgramAtTheStartup()
    
    client.connect_to_server()

    os.system('pause')
