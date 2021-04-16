############################################################
#                                                          #
# Author: Sergio Garcia Lopez                              #
#                                                          #
# GitHub: https://github.com/SergiDelta/SecureServer       #
#                                                          #
# Date: April 2021                                         #
#                                                          #
# Description: Client programm example for SecureServer.py #
#                                                          #
############################################################

import socket
import ssl
import sys
import select

if len(sys.argv) != 3:
   print("Use: " + sys.argv[0] + " <host> " + "<port>")
   sys.exit()

host = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
ctx.minimun_version = ssl.PROTOCOL_TLSv1_2
ctx.check_hostname = False
ctx.load_default_certs()
ssock = ctx.wrap_socket(sock)


try:
   print("Trying to connect...")
   ssock.connect((host,port))

except socket.error as e:
   print(e)
   sys.exit()

print("Connected")

try:

   while True:

      try:

         rlist, wlist, xlist = select.select([ssock], [], [], 0.5)

         if [rlist, wlist, xlist] != [ [], [], [] ]:

            rx_msg = ssock.recv(1024)
            rx_decoded = rx_msg.decode()

            if rx_decoded[ len(rx_decoded) - 1 ] == '\n':
               rx_list = list(rx_decoded)
               rx_list[ len(rx_decoded) - 1 ] = ''
               rx_decoded = ''.join(rx_list)

            print(rx_decoded)

            if rx_decoded.find("Timeout") != -1:
               break

         tx_msg = input(">> ")
         ssock.sendall( (tx_msg + "\n").encode() )

      except socket.error:
         break

except KeyboardInterrupt:
   print()
