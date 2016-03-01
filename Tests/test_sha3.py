#!/usr/bin/python
# -*-coding:Utf-8 -*

import hashlib
import sha3
from binascii import hexlify, unhexlify
from potr.compatcrypto import HASH

print 'Début des tests sur la fonction HASH et de SHA3'

# Test short messages
with open('./sha3/shortmsg.txt') as f_msg:
    with open('./sha3/shortmsg_fingerprint.txt') as f_ref:
   		for line in f_msg:
   		
			hex_msg = line.rstrip()
			ref = f_ref.readline().rstrip()
			bin_msg = unhexlify(hex_msg)
			hash_msg = hashlib.sha3_256(bin_msg).hexdigest()
			
			assert (hash_msg == ref), (hex_msg, bin_msg, hash_msg, ref)

# Test long messages
with open('./sha3/longmsg.txt') as f_msg:
    with open('./sha3/longmsg_fingerprint.txt') as f_ref:
		for line in f_msg:
		
			hex_msg = line.rstrip()
			ref = f_ref.readline().rstrip()
			
			bin_msg = unhexlify(hex_msg)
			hash_msg = hashlib.sha3_256(bin_msg).hexdigest()
			
			assert (hash_msg == ref), (hex_msg, bin_msg, hash_msg, ref)
	
# Test HASH OTR

# Test short messages
with open('./sha3/shortmsg.txt') as f_msg:
    with open('./sha3/shortmsg_fingerprint.txt') as f_ref:
		for line in f_msg:
    	
			hex_msg = line.rstrip()
			ref = f_ref.readline().rstrip()
			
			bin_msg = unhexlify(hex_msg)
			hash_msg = hexlify(HASH(bin_msg))
			
			assert (hash_msg == ref), (hex_msg, bin_msg, hash_msg, ref)

# Test long messages
with open('./sha3/longmsg.txt') as f_msg:
    with open('./sha3/longmsg_fingerprint.txt') as f_ref:
		for line in f_msg:
		
			hex_msg = line.rstrip()
			ref = f_ref.readline().rstrip()
			
			bin_msg = unhexlify(hex_msg)
			hash_msg = hexlify(HASH(bin_msg))
			
			assert (hash_msg == ref), (hex_msg, bin_msg, hash_msg, ref)

print "Tests de la fonction HASH et de SHA3 OK !"
