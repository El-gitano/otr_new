#!/usr/bin/python
# -*-coding:Utf-8 -*

from potr.compatcrypto import HMAC
from binascii import hexlify, unhexlify

# Test short messages
with open('./hmac_sha512/datas.txt') as f_datas:
	with open('./hmac_sha512/keys.txt') as f_keys:
		with open('./hmac_sha512/hmac.txt') as f_ref:
			for line in f_datas:
   			
				hex_data = line.rstrip()
				hex_key = f_keys.readline().rstrip()
				hex_ref = f_ref.readline().rstrip()
				
				bin_data = unhexlify(hex_data)
				bin_key = unhexlify(hex_key)
				
				tag = HMAC(bin_key, bin_data)
				hex_tag = hexlify(tag)
				
				assert (hex_tag == hex_ref), (hex_data, hex_key, hex_tag, hex_ref)
				
print "Tests de la fonction HMAC et de HMAC_SHA512 OK !"
