################################################################
#						               #
# Author: Sergio Garcia Lopez                                  #
#			    			               #
# GitHub: https://github.com/SergiDelta/SecureServer           #
#                                                              #
# Date: April 2021				               #
#				                               #
# Description: Simple server that uses threads                 #
#              to handle TCP connections and the TLS/SSL       #
#              python module to encrypt the communications.    #
#              It includes chat records, timeout handling and  #
#              broadcasting.                                   #
#						               #
################################################################

import socket
import ssl
import sys
import threading
import datetime
import re
import traceback

timeout = 30
certfile = "cert.pem"
keyfile = "key.pem"

def tls_wrap_socket(sock):

      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
      ctx.minimun_version = ssl.PROTOCOL_TLSv1_2
      ctx.load_cert_chain(certfile, keyfile)

      ssock = ctx.wrap_socket(sock, server_side=True)

      return ssock

class SecureServer:

   def __init__(self, addr, file):

      self.host = addr[0]
      self.port = addr[1]
      self.socklist = []
      self.record = file
      self.serversock = tls_wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM) )
      self.serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      self.socklist.append(self.serversock)
      print("Socket created")

      try:
         self.serversock.bind( (self.host,self.port) )
      except socket.error as e:
         msg = "Failed at binding socket to [" + self.host + ":" + str(self.port) + "] address."
         msg += " Error number: " + str(e.errno) + ". Message: " + e.strerror + "\n"
         print(msg)
         self.record.close()
         self.socklist.remove(self.serversock)
         self.serversock.close()
         sys.exit()

      print("Socket binded")

      self.serversock.listen(10)
      print("Server listening on port " + str(self.port) + "\n")
      self.record.write("<-- New session: " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") +" -->\n\n" )

   def clientthread(self, conn):

      try:

         self.socklist.append(conn)
         addr = conn.getpeername()
         conn.settimeout(timeout)
         conn.sendall("Welcome to the server. Type something and hit enter\r\n".encode() )

         while True:

            try:

               data = conn.recv(1024)

            except socket.timeout as t:

               print("Timeout. ", end='' )
               self.record.write("Timeout. ")
               break

            if not data:
               break

            try:

               msg = data.decode()

            except UnicodeDecodeError:

               msg = "###" + " Bad payload " + "###"
               fullmsg = "[" + addr[0] + ":" + str(addr[1]) + "] " + msg + "\n"
               print(fullmsg)
               self.record.write(fullmsg)

               continue

            if msg != "\r\n" and msg != "\n" and msg != "" and msg != "\0":
               self.broadcast(msg, conn)

         self.socklist.remove(conn)
         conn.sendall("Timeout. Connection lost with server\r\n".encode() )
         conn.close()
         print("Connection closed with [" + addr[0] + ":" + str(addr[1]) + "]\n" )
         self.record.write("Connection closed with [" + addr[0] + ":" + str(addr[1]) + "]\n")

      except socket.error as e:
         msg = "Error number: " + str(e.errno) + ". Message: " + e.strerror + "\n"
         print(msg)
         self.record.write(msg)
         self.socklist.remove(conn)
         conn.close()

      except ssl.SSLError as e:
         print(e)
         self.record.write(e + "\n")
         self.socklist.remove(conn)
         conn.close()

   def broadcast(self, msg, sender):

      addr = sender.getpeername()
      fullmsg = "[" + addr[0] + ":" + str(addr[1]) + "] " + msg + "\r"

      for sock in self.socklist:
         if sock != self.serversock and sock != sender:
            sock.sendall(fullmsg.encode() )

      print(fullmsg)
      self.record.write(fullmsg)

   def run(self):

      while True:

         try:
            conn, addr = self.serversock.accept()
         except ssl.SSLError:
            continue
         except socket.error:
            continue

         print("Connected with [" + addr[0] + ":" + str(addr[1]) + "]\n" )
         self.record.write("Connected with [" + addr[0] + ":" + str(addr[1]) + "]\n")

         threading.Thread(target=self.clientthread, args=(conn,) ).start()

def main():

   if len(sys.argv) != 3:
      print("Use: " + sys.argv[0] + " <IP> " + "<port>")
      sys.exit()

   ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

   if ip_pattern.search(sys.argv[1]) == None:
      print("Invalid IP address")
      sys.exit()

   if sys.argv[2].isdigit() == False:
      print("Port must be a number (integer)")
      sys.exit()

   host = sys.argv[1]
   port = int(sys.argv[2])

   if (port >= 0 and port <= 65535) == False:
      print("Invalid port (must be 0-65535)") 
      sys.exit()

   file = open("record.log", "a")

   try:
      myServer = SecureServer( (host, port) , file)
      myServer.run()
   except KeyboardInterrupt:
      print()
   except Exception:
      traceback.print_exc()
      file.write( traceback.format_exc() )

   file.write("\n<-- Session closed: " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " -->\n\n")
   file.close()

if __name__ == "__main__":
   main()
