# -*- coding: utf-8 -*

import socket
from threading import Condition, Thread, Timer
from multiprocessing import Manager
import os
import json
import time
from hashlib import new, sha256
import codecs
import struct
import pickle
import platform
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
        self.idWork = 0


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
            # publicIp = requests.get('https://api.ipify.org').text

            # if(publicIp == self.config['remote-server-host']):
                
            self.host = self.config['server-host']
            self.port = self.config['server-port']

            # else:
                # self.host = self.config['remote-server-host']
                # self.port = self.config['remote-server-port']
        except:
            print("[Internet connection Error]")
            self.host = self.config['server-host']
            self.port = self.config['server-port']
            pass



    def evalute(self):

        # >
        begin = time.perf_counter()
        target = '000000000000000000001ff2ef9f6a1af873fcf4b7a516f0370d167804be6539'
        header = [
            {
                "version" : 939515908,
                "prevBlock" : "000000000000000000021ff2ef9f6a1af873fcf4b7a516f0370d167804be6539",
                "merkleRoot" : "7556f11328ef3a0d89dfe04178c138103b0207b6d5dceedabb4e176b9a043758",
                "creationTime" : 1625497026,
                "bits" : 0x171398ce,
                "nonce" : 2006663886
            }
        ]

        Min, Max = (1_000_000, 2_000_000)
        data = [{
            'max_nonce': Max,
            'min_nonce': Min,
            'target': int(target, 16)
        }]

        test = Miner(data=data, header=header, desc='[EVALUATION TEST]')
        test.start()
        test.join()
        # self.miner(Min, Max, header, target)

        end = time.perf_counter()
        hps = (end -begin)


        return hps



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
                # sendCurrentStateOfWorkToTheServer = repeatTimer(60, self.sendStatuOfWorkToServer)
                # sendCurrentStateOfWorkToTheServer.start()

            except TimeoutError:
                if cpt == 1:
                    print('[The server is not available.]')                
                # os.system(self.clearConsCmd)                
                pass

            except ConnectionRefusedError:
                if cpt == 1:
                    print("[Please wait a moment we are performing maintenance actions on the server.]")
                # os.system(self.clearConsCmd)                
                pass

            except AttributeError:
                if cpt == 1:
                    print('[Internal server error.]')
                pass

            except:
                if cpt == 1:
                    print("[Unknow error occured]")
                pass
                        
            data = [{
                "type": 0,
                "hps": hps
            }]
            if self.connect:
                try:
                    self.client.send(pickle.dumps(data))
                    with Manager() as manager:
                        data = manager.list()
                        newBlockHasBeenSend = manager.Event()

                        while True:
                            data_receive = self.client.recv(2048)
                            
                            if(data_receive):

                                data_receive = pickle.loads(data_receive)
                                
                                # verifyIfNewWorkHasBeenSend = repeatTimer(1, self.recieve)
                                # verifyIfNewWorkHasBeenSend.start()

                                if self.idWork < data_receive['idWork']:
                                    
                                    self.idWork += 1
                                    newBlockHasBeenSend.clear()
                                    
                                    header = [data_receive]
                                    target = self.GetTarget(hex(data_receive['bits'])[2:])
                                    data_receive['target'] = target
                                    data.append(data_receive)
                                    print('new has been send : ',newBlockHasBeenSend.is_set())
                                
                                    resultOfMining= Miner(data= data, header=header, desc='[SEARCH]', newBlockHasBeenSend=newBlockHasBeenSend, client=self.client, hps=hps)
                                    resultOfMining.start()
                                    # resultOfMining.join()    



                except BrokenPipeError:
                    if cpt == 1:
                        print('[Errno 32] Broken pipe')
                    break

                # except OSError:
                #     if cpt == 1:
                #         print("Errors")
                #     break

                except ConnectionResetError:
                    if cpt == 1:
                        print('[Errno 54] Connection reset by peer')
                        print('Attempting new connection')

                        os.system(self.clearConsCmd)
                    break

                # except:
                #     if cpt == 1:
                #         print("Unknow error")
                #     break

            cpt += 1
            
        self.client.close()



class Miner(Thread):
    
    def __init__(self, data, header, desc, newBlockHasBeenSend=None, client=None, hps=None):

        Thread.__init__(self)

        if newBlockHasBeenSend != None:
            self.hps = hps
            self.client = client
            self.newBlockHasBeenSend = newBlockHasBeenSend
        else:
            self.hps = None
            self.newBlockHasBeenSend = False

        self.min_nonce = data[0]['min_nonce']
        self.max_nonce = data[0]['max_nonce']
        self.header = header
        self.target = data[0]['target']
        self.desc = desc

    def sendStatuOfWorkToServer(self):

        data = {
            'type': 3,
            'rest_of_work': [self.nonce, self.Max]
        }
        if self.connect:
            try:
                self.client.send(pickle.dumps([data]))
            except:
                self.connect = False
                pass

    def recieve(self):
        try:
            recv = self.client.recv(2048)

            if recv:
                self.newBlockHasBeenSend = True
                self.work = pickle.loads(recv)

        except:
            self.connect = False
            # print('The Connection was closed by the server. Please retry another connection')
            pass


    def run(self):
        
        version = self.header[0]["version"]
        prevBlockId= self.header[0]["prevBlock"]
        merkleRoot = self.header[0]["merkleRoot"]
        Time = self.header[0]["creationTime"]
        bits = self.header[0]["bits"]

        Min, Max = self.min_nonce, self.max_nonce

        self.nonce = Min

        print(f'Range of Work : [{Min}; {Max}] \n')
        
        for _ in tqdm(range(Min, Max), desc=self.desc):
            if self.hps != None:
                if(not self.newBlockHasBeenSend.is_set()):
                    print("work")
                    hash = self.HashHeader(version, prevBlockId, merkleRoot, Time, bits, self.nonce)
                    if(hash < self.target):

                        self.header[0]['nonce'] = self.nonce
                        self.header[0]['type'] = 1
                        self.client.send(pickle.dumps(self.header))

                else:
                    self.header[0]['type'] = 2
                    self.header[0]['hps'] = self.hps
                    try:
                        self.client.send(pickle.dumps(self.header))
                    except:
                        break

            else:
                if(not self.newBlockHasBeenSend):
                    
                    hash = self.HashHeader(version, prevBlockId, merkleRoot, Time, bits, self.nonce)
                    if(hash < self.target):

                        self.header[0]['nonce'] = self.nonce
                        self.header[0]['type'] = 1
                        self.client.send(pickle.dumps(self.header))

                else:
                    self.header[0]['type'] = 2
                    self.header[0]['hps'] = self.hps
                    try:
                        self.client.send(pickle.dumps(self.header))
                    except:
                        break


                                # else:

        # if self.newBlockHasBeenSend:
        #     data_receive = self.work
        #     header = [self.work]
        #     target = self.GetTarget(hex(data_receive['bits'])[2:])
        #     self.newBlockHasBeenSend = False                        
        #     self.SearchOfGoodNonce(data_receive['nonce'][0], data_receive['nonce'][1], header, target, desc='[SEARCH]')
        
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

    
    def sending(self, data):

        # self.client.send(typeOfMsg.encode())
        self.client.send(pickle.dumps(data))




if __name__ == '__main__':

    client = CLIENT()

    client.launchProgramAtTheStartup()
    
    client.connect_to_server()

    os.system('pause')
