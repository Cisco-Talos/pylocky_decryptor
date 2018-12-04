/*
 * Copyright 2018, Cisco Systems, Inc. (Talos)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *     Author: Mike Bautista
 */
 
import os, argparse
import re
import base64
import urllib
import urlparse
import hashlib
import threading
import string
from os.path import expanduser
from Crypto.Cipher import DES3
from scapy.all import *
import traceback
import sys

password = ""
iv = ""
debug = False
remove = False
counter = 0

def read_pcap(packet):
    payload = str(packet[TCP].payload)
    if len(payload) > 0:
        regex = r".*&iv=.*&password=.*"
        params = re.search(regex,payload,re.M|re.I)
        if params:
            i = 0
            values = params.group(0).split('&')
            while i < len(values):
                if "PASSWORD" in values[i]:
                    global password
                    password = urllib.unquote(values[i]).decode('utf8').strip().split('PASSWORD=')[1]
                    if debug:
                        print("Extracted password from pcap: "+password)
                if "IV" in values[i]:
                    global iv
                    iv = urllib.unquote(values[i]).decode('utf8').strip().split('IV=')[1]
                    iv = iv.decode("base64")
                    if debug:
                        print("Extracted iv from pcap: "+iv)
                i += 1

def _make_des3_decryptor(key, iv):
    if debug:
        print("Before getting decryptor")
    decryptor = DES3.new(key, DES3.MODE_CBC, iv)
    if debug:
        print("Decryptor returned")
    return decryptor

def des3_decrypt(key, iv, data, debug):
    decryptor = _make_des3_decryptor(key, iv)
    if debug:
        print("Before decrypting data")
    result = decryptor.decrypt(data)
    pad_len = ord(result[-1])
    result = result[:-pad_len]
    return result


def dfile(fname, password, iv,debug):
    ## DEFAULT FILETYPES TO DECRYPT
    DECRYPTABLE_FILETYPES = [
	# Lockedfiles
	"lockedfile"
            ]

    if "LOCKY-README.txt" in fname:
        os.remove(fname)
        if debug:
            print("Removed ransom message file: "+fname)
        return 0

    if "lockedfile" in fname:
        global counter
        fname_w_e = os.path.splitext(fname)[0]
        if debug:
            print("Opening fname: "+fname)
        fd = open(fname, "rb")
        data = fd.read()
        fd.close()
        if debug:
            print("Closed fname: "+fname)
        ddata = des3_decrypt(password, iv, data, debug)
        rdata = ddata.decode("base64")
        if debug:
            print("Opening fname_w_e: "+fname_w_e)
        fd = open(fname_w_e, "wb")
        fd.write(rdata)
        fd.close()
        if debug:
            print("Closed fname_w_e: "+fname_w_e)
        if debug:
            print("File processed correctly: "+fname)
        if remove:
            os.remove(fname)
            if debug:
                print("File removed correctly: "+fname)
        counter += 1

def dstart(drive, password, iv,debug):
    for path, dirs, filenames in os.walk(drive):
        for f in filenames:
            file = os.path.join(path, f)
            try:
                dfile(file, password, iv,debug)
            except Exception:
                print(traceback.format_exc())
    return 0

def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1

    return drives

def main():
    global counter
    opt=argparse.ArgumentParser(description="PyLocky decryptor")
    opt.add_argument("-p", "--pcap", action="store", dest="file", help="Provide PyLocky C&C pcap", metavar="pylocky.pcap")
    opt.add_argument("-r", "--remove", action="store_true", help="Remove encrypted files")
    opt.add_argument("-d", "--debug", action="store_true", help="Debug this program")

    if len(sys.argv)<=1:
        opt.print_help()
        sys.exit(1)

    options = opt.parse_args()
    if options.remove:
        global remove
        remove = True

    if options.file:
       sniff(filter="dst port 80",offline=options.file,prn=read_pcap,store=0)

    if password == "":
        print("Password is empty")
        sys.exit(1)

    if iv == "":
        print("IV is empty")
        sys.exit(1)

    home = expanduser("~")

    if options.debug:
        global debug
        debug = True
        print("Password to decrypt with: "+password)
        print("IV (base64 decoded) to decrypt with: "+iv)

    edisk = get_drives()

    for d in edisk:
        if "C" in d:
            t = threading.Thread(target=dstart, args=(home, password, iv,options.debug))
            t.start()
            t.join()
        else:
            t = threading.Thread(target=dstart, args=(d, password, iv,options.debug))
            t.start()
            t.join()

    if counter > 0:
        print("Decryption complete! Please verify the content of your files and system")
    else:
        print('No files with the ".lockedfile" extension were found. Please check again')

if __name__ == '__main__':
    main()
