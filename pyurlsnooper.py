#!/usr/bin/python

# This software is provided under under Public Domain. See the accompanying
# license on https://sourceforge.net/projects/pyurlsnooper/ for more
# information. Although THIS script is released with following additional
# restrictions:
# --------------------------------------------------------------------------------
# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Authors:
#  Maximiliano Caceres <max@coresecurity.com>
#  Javier Kohen <jkohen@coresecurity.com>
#
# Reference for:
#  pcapy: findalldevs, open_live.
#  ImpactDecoder.
# --------------------------------------------------------------------------------
#
# $Id: pyurlsnooper.py,v 1.1 2010/02/01 18:50:00 drtrigon $
#
# Simple URL packet sniffer.
#
# This packet sniffer uses the pcap library to listen for packets in
# transit over the specified interface. The returned packages can be
# filtered according to a BPF filter (see tcpdump(3) for further
# information on BPF filters). Look also at sniff.py from pcapy at
# http://oss.coresecurity.com/impacket/sniff.py
# http://oss.coresecurity.com/projects/pcapy.html
#
# Note that the user might need special permissions to be able to use pcap.
#
# Run this script:
#     linux: - open terminal/shell
#            - run "su -c 'python pyurlsnooper.py'" to execute the script with
#              root permissions
#            - to quit the script while it is running, press any key
#   windows: - open command-line as administrator (to execute the script with
#              admin permissions)
#            - run "python pyurlsnooper.py"
#            - to quit the script while it is running, press any key
#
# Look also at README for further details.
#
# Search for:
#  URL Snooper (Windows)
#  pcapy, ImpactDecoder, ...


import sys
import string
from threading import Thread

import pcapy
from pcapy import findalldevs, open_live
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

import re, PyLib


# this regex should be improoved, because it already caused some problems (e.g. on southpark.de, ...)
regex_links = re.compile("((https?|ftp|gopher|telnet|file|notes|ms-help|rtmp|rtmpe):((//)|(\\\\))[\w\d:#%/;$()~_?\-=\\\.&!]*)")


class DecoderThread(Thread):
    """
    Main decoder/network sniffer class (running in separate thread).
    """

    def __init__(self, pcapObj):
        """ Query the type of the link and instantiate a decoder accordingly. """
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        Thread.__init__(self)

    def run(self):
        """ Sniff ad infinitum.
            PacketHandler shall be invoked by pcap for every packet. """
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        """ Use the ImpactDecoder to turn the rawpacket into a hierarchy
            of ImpactPacket instances.
            Display the packet in human-readable form.
            http://d.hatena.ne.jp/shoe16i/mobile?date=20090203&section=p1 """
        decoded_data = self.decoder.decode(data)
        tcp = decoded_data.child().child()
        data = tcp.get_packet()
        decoded_data = data
        for item in regex_links.finditer(str(decoded_data)):
            if not item: continue
            pos = item.start()
            print item.groups()[0], "\n"


def getInterface():
    """  Grab a list of interfaces that pcap is able to listen on.
         The current user will be able to listen from all returned interfaces,
         using open_live to open them. """
    ifs = findalldevs()

    # No interfaces available, abort.
    if 0 == len(ifs):
        print "You don't have enough permissions to open any interface on this system."
        sys.exit(1)

    # Only one interface available, use it.
    elif 1 == len(ifs):
        print 'Only one interface present, defaulting to it.'
        return ifs[0]

    # Ask the user to choose an interface from the list.
    count = 0
    for iface in ifs:
        print '%i - %s' % (count, iface)
        count += 1
    idx = int(raw_input('Please select an interface: '))

    return ifs[idx]

def main(filter):
    dev = getInterface()

    # Open interface for catpuring.
    p = open_live(dev, 1500, 0, 100)

    # Set the BPF filter. See tcpdump(3).
    p.setfilter(filter)

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink())

    # Start sniffing thread and finish main thread.
    DecoderThread(p).start()



#logfile = open('urlsnooper','w')
logfile = open('urlsnooper','a')
sys.stdout = PyLib.RedirStream(logfile)#, stdstream=False)
sys.stderr = PyLib.RedirStream(logfile)#, stdstream=False)

main('')
raw_input("Press any key to quit...\n")		# wait until key pressed...

del sys.stdout, sys.stderr
logfile.close()
sys.exit()

