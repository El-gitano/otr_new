# -*-coding:Utf-8 -*
#    Copyright 2012 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

import logging

from Crypto import Cipher

# Nouveau
import sha3
import hashlib
import hmac as _HMAC
from Crypto.Hash import SHA512 as _SHA512

from Crypto.Random import random
from ecdsa import SigningKey, VerifyingKey, NIST384p
from numbers import Number

from potr.compatcrypto import common
from potr.utils import read_mpi, bytes_to_long, long_to_bytes, read_data

def HASH(data):
	return hashlib.sha3_256(data).digest()

def HMAC(key, data):
	return SHA512HMAC(key, data)

def HMAC160(key, data):
	return SHA512HMAC(key, data)[:20]

def SHA512HMAC(key, data):
	return _HMAC.new(key, msg=data, digestmod=_SHA512).digest()

def AESCTR(key, counter=0):
    if isinstance(counter, Number):
        counter = Counter(counter)
    if not isinstance(counter, Counter):
        raise TypeError
    return Cipher.AES.new(key, Cipher.AES.MODE_CTR, counter=counter)

class Counter(object):
    def __init__(self, prefix):
        self.prefix = prefix
        self.val = 0

    def inc(self):
        self.prefix += 1
        self.val = 0

    def __setattr__(self, attr, val):
        if attr == 'prefix':
            self.val = 0
        super(Counter, self).__setattr__(attr, val)

    def __repr__(self):
        return '<Counter(p={p!r},v={v!r})>'.format(p=self.prefix, v=self.val)

    def byteprefix(self):
        return long_to_bytes(self.prefix, 8)

    def __call__(self):
        bytesuffix = long_to_bytes(self.val, 8)
        self.val += 1
        return self.byteprefix() + bytesuffix

@common.registerkeytype
class ECDSAKey(common.PK):
	
	keyType = 0x0001

	# Creation de la cle de signature
	# Si key est specifie la cle est cree depuis le parametre, sinon elle est auto-generee
	def __init__(self, key=None, private=False):
		
		self.secretKey = self.verifKey = None
		
		# Recuperation
		if key is not None:
			if private:
				self.secretKey = SigningKey.from_string(key, curve=NIST384p)
				self.verifKey = self.secretKey.get_verifying_key()
			else:
				self.verifKey = VerifyingKey.from_string(key, curve=NIST384p)
		
		# Auto-generation	
		else:
			self.secretKey = SigningKey.generate(curve=NIST384p)
			self.verifKey = self.secretKey.get_verifying_key()
			
	def getPublicPayload(self):
		return self.verifKey.to_string()

	def getPrivatePayload(self):
		return self.secretKey.to_string()

	def fingerprint(self):
		return HASH(self.getSerializedPublicPayload())

	def sign(self, data):
		return self.secretKey.sign(data)

	def verify(self, data, sig):
		return self.verifKey.verify(sig, data)

	def __hash__(self):
		return bytes_to_long(self.fingerprint())

	def __eq__(self, other):
		if not isinstance(other, type(self)):
			return False
		return self.fingerprint() == other.fingerprint()

	def __ne__(self, other):
		return not (self == other)

	@classmethod
	def generate(cls):
		return cls()
		
	@classmethod
	def parsePayload(cls, data, private=False):
		serializedKey, data = read_data(data)
		key = cls(serializedKey, private)
		return  key, data
