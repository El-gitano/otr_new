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

import hashlib
import sha3
import hmac as _HMAC

from Crypto.Hash import SHA512 as _SHA512
from Crypto.Random import random

from potr.compatcrypto import common
from potr.utils import read_mpi, bytes_to_long, long_to_bytes, read_data

from binascii import hexlify
from ecdsa import SigningKey, VerifyingKey, NIST384p
from numbers import Number

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
		
# Définit une courbe elliptique
class EllipticCurve(object):

	def __init__(self, nom, p, a, b, g, n, h):
	
		self.nom = nom
		self.p = p
		self.a = a
		self.b = b
		self.g = g
		self.n = n
		self.h = h

	def is_on_curve(self, point):
	
		"""Returns True if the given point lies on the elliptic curve."""
		if point is None:
		    # None represents the point at infinity.
		    return True

		x, y = point

		return (y * y - x * x * x - self.a * x - self.b) % self.p == 0	
	
	def point_neg(self, point):
	
		"""Returns -point."""
		assert self.is_on_curve(point)

		if point is None:
		    # -0 = 0
		    return None

		x, y = point
		result = (x, -y % self.curve.p)

		assert self.is_on_curve(result)

		return result
		
	def point_add(self, point1, point2):
		"""Returns the result of point1 + point2 according to the group law."""
		assert self.is_on_curve(point1)
		assert self.is_on_curve(point2)

		if point1 is None:
		    # 0 + point2 = point2
		    return point2
		if point2 is None:
		    # point1 + 0 = point1
		    return point1

		x1, y1 = point1
		x2, y2 = point2

		if x1 == x2 and y1 != y2:
		    # point1 + (-point1) = 0
		    return None

		if x1 == x2:
		    # This is the case point1 == point2.
		    m = (3 * x1 * x1 + self.a) * self.inverse_mod(2 * y1, self.p)
		else:
		    # This is the case point1 != point2.
		    m = (y1 - y2) * self.inverse_mod(x1 - x2, self.p)

		x3 = m * m - x1 - x2
		y3 = y1 + m * (x3 - x1)
		result = (x3 % self.p,
		          -y3 % self.p)

		assert self.is_on_curve(result)

		return result

	def scalar_mult(self, k, point):
		"""Returns k * point computed using the double and point_add algorithm."""
		assert self.is_on_curve(point)

		if k % self.n == 0 or point is None:
		    return None

		if k < 0:
		    # k * point = -k * (-point)
		    return self.scalar_mult(-k, self.point_neg(point))

		result = None
		addend = point

		while k:
		    if k & 1:
		        # Add.
		        result = self.point_add(result, addend)

		    # Double.
		    addend = self.point_add(addend, addend)

		    k >>= 1

		assert self.is_on_curve(result)

		return result
	
	def inverse_mod(self, k, p):
		"""
		Returns the inverse of k modulo p.

		This function returns the only integer x such that (x * k) % p == 1.

		k must be non-zero and p must be a prime.
		"""
		if k == 0:
		    raise ZeroDivisionError('division by zero')

		if k < 0:
		    # k ** -1 = p - (-k) ** -1  (mod p)
		    return p - self.inverse_mod(-k, p)

		# Extended Euclidean algorithm.
		s, old_s = 0, 1
		t, old_t = 1, 0
		r, old_r = p, k

		while r != 0:
		    quotient = old_r // r
		    old_r, r = r, old_r - quotient * r
		    old_s, s = s, old_s - quotient * s
		    old_t, t = t, old_t - quotient * t

		gcd, x, y = old_r, old_s, old_t

		assert gcd == 1
		assert (k * x) % p == 1

		return x % p

# Définit les variables impliquées dans une échange ECDH				
class ECDH(object):

	def __init__(self):
		
		self.curve = EllipticCurve('secp256k1', p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, a=0, b=7,	g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8), n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, h=1)

		self.priv = random.randrange(1, self.curve.n)
		self.pub = self.curve.scalar_mult(self.priv, self.curve.g)

	def get_serialized_pubKey(self):
		return self.serialize_pubKey(self.pub)
	
	def get_serialized_privKey(self):
		return pack_mpi(self.priv)
	
	@classmethod
	def serialize_pubKey(cls, pubKey):
		return pack_mpi(pubKey[0])+pack_mpi(pubKey[1])
	
	@classmethod
	def parse_serialized_privKey(cls, serializedPrivKey):
		return read_mpi(serializedPrivKey)[0]
	
	@classmethod
	def parse_serialized_pubKey(cls, serializedPubKey):
	
		a, data = read_mpi(serializedPubKey)
		b = read_mpi(data)[0]
		
		return (a, b)
	
	def get_shared_secret(self, pubKey):
		
		commonPoint = self.curve.scalar_mult(self.priv, pubKey)
		sharedSecret = int(hexlify(HASH(hex(commonPoint[0]) + hex(commonPoint[1]))), 16)
		
		return sharedSecret

