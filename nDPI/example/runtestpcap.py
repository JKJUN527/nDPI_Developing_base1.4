#!/usr/bin/python 
import sys
import os
#print "arguments is:"
#for i in sys.argv:
#print sys.argv[1]
os.system('make && ./pcapReader -i /root/Desktop/'+sys.argv[1]+' >/root/Desktop/'+sys.argv[1]+'.log')
