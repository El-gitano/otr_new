# -*-coding:Utf-8 -*
#	Copyright 2011-2012 Kjell Braden <afflux@pentabarf.de>
#
#	This file is part of the python-potr library.
#
#	python-potr is free software; you can redistribute it and/or modify
#	it under the terms of the GNU Lesser General Public License as published by
#	the Free Software Foundation; either version 3 of the License, or
#	any later version.
#
#	python-potr is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU Lesser General Public License for more details.
#
#	You should have received a copy of the GNU Lesser General Public License
#	along with this library.  If not, see <http://www.gnu.org/licenses/>.

# some python3 compatibilty
from __future__ import unicode_literals

import logging
import struct


from potr.compatcrypto import SHA256, SHA1, SHA1HMAC, SHA256HMAC, \
		SHA256HMAC160, Counter, AESCTR, PK, random
from potr.utils import bytes_to_long, long_to_bytes, pack_mpi, read_mpi
from potr import proto

logger = logging.getLogger(__name__)

STATE_NONE = 0
STATE_AWAITING_DHKEY = 1
STATE_AWAITING_REVEALSIG = 2
STATE_AWAITING_SIG = 4
STATE_V1_SETUP = 5


DH_MODULUS = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
DH_MODULUS_2 = DH_MODULUS-2
DH_GENERATOR = 2
DH_BITS = 1536
DH_MAX = 2**DH_BITS
SM_ORDER = (DH_MODULUS - 1) // 2

def check_group(n):
	return 2 <= n <= DH_MODULUS_2
	
def check_exp(n):
	return 1 <= n < SM_ORDER

# Définit une courbe elliptique
class EllipticCurve:

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
class ECDH:

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
		result = self.curve.scalar_mult(self.priv, pubKey)[0]
		return result

'''
class DH(object):

	@classmethod
	def set_params(cls, prime, gen):
		cls.prime = prime
		cls.gen = gen

	def __init__(self):
		self.priv = random.randrange(2, 2**320)
		self.pub = pow(self.gen, self.priv, self.prime)

DH.set_params(DH_MODULUS, DH_GENERATOR)
'''

class DHSession(object):
	def __init__(self, sendenc, sendmac, rcvenc, rcvmac):
		self.sendenc = sendenc
		self.sendmac = sendmac
		self.rcvenc = rcvenc
		self.rcvmac = rcvmac
		self.sendctr = Counter(0)
		self.rcvctr = Counter(0)
		self.sendmacused = False
		self.rcvmacused = False

	def __repr__(self):
		return '<{cls}(send={s!r},rcv={r!r})>' \
				.format(cls=self.__class__.__name__,
						s=self.sendmac, r=self.rcvmac)

	@classmethod
	def create(cls, dh, y):

		s = dh.get_shared_secret(y)
		sb = pack_mpi(s)

		if dh.pub[0] > y[0]:
			sendbyte = b'\1'
			rcvbyte = b'\2'
		else:
			sendbyte = b'\2'
			rcvbyte = b'\1'

		sendenc = SHA1(sendbyte + sb)[:16]
		sendmac = SHA1(sendenc)
		rcvenc = SHA1(rcvbyte + sb)[:16]
		rcvmac = SHA1(rcvenc)
		return cls(sendenc, sendmac, rcvenc, rcvmac)

class CryptEngine(object):
	def __init__(self, ctx):
		self.ctx = ctx
		self.ake = None

		self.sessionId = None
		self.sessionIdHalf = False
		self.theirKeyid = 0
		self.theirY = None
		self.theirOldY = None

		self.ourOldDHKey = None
		self.ourDHKey = None
		self.ourKeyid = 0

		self.sessionkeys = {0:{0:None, 1:None}, 1:{0:None, 1:None}}
		self.theirPubkey = None
		self.savedMacKeys = []

		self.smp = None
		self.extraKey = None

	def revealMacs(self, ours=True):
		if ours:
			dhs = self.sessionkeys[1].values()
		else:
			dhs = ( v[1] for v in self.sessionkeys.values() )
		for v in dhs:
			if v is not None:
				if v.rcvmacused:
					self.savedMacKeys.append(v.rcvmac)
				if v.sendmacused:
					self.savedMacKeys.append(v.sendmac)

	def rotateDHKeys(self):
		self.revealMacs(ours=True)
		self.ourOldDHKey = self.ourDHKey
		self.sessionkeys[1] = self.sessionkeys[0].copy()
		self.ourDHKey = ECDH()
		self.ourKeyid += 1

		self.sessionkeys[0][0] = None if self.theirY is None else \
				DHSession.create(self.ourDHKey, self.theirY)
		self.sessionkeys[0][1] = None if self.theirOldY is None else \
				DHSession.create(self.ourDHKey, self.theirOldY)

		logger.debug('{0}: Refreshing ourkey to {1} {2}'.format(
				self.ctx.user.name, self.ourKeyid, self.sessionkeys))

	def rotateYKeys(self, new_y):
		self.theirOldY = self.theirY
		self.revealMacs(ours=False)
		self.sessionkeys[0][1] = self.sessionkeys[0][0]
		self.sessionkeys[1][1] = self.sessionkeys[1][0]
		self.theirY = new_y
		self.theirKeyid += 1

		self.sessionkeys[0][0] = DHSession.create(self.ourDHKey, self.theirY)
		self.sessionkeys[1][0] = DHSession.create(self.ourOldDHKey, self.theirY)

		logger.debug('{0}: Refreshing theirkey to {1} {2}'.format(
				self.ctx.user.name, self.theirKeyid, self.sessionkeys))

	def handleDataMessage(self, msg):
		if self.saneKeyIds(msg) is False:
			raise InvalidParameterError

		sesskey = self.sessionkeys[self.ourKeyid - msg.rkeyid] \
				[self.theirKeyid - msg.skeyid]

		logger.debug('sesskeys: {0!r}, our={1}, r={2}, their={3}, s={4}' \
				.format(self.sessionkeys, self.ourKeyid, msg.rkeyid,
						self.theirKeyid, msg.skeyid))

		if msg.mac != SHA1HMAC(sesskey.rcvmac, msg.getMacedData()):
			logger.error('HMACs don\'t match')
			raise InvalidParameterError
		sesskey.rcvmacused = True

		newCtrPrefix = bytes_to_long(msg.ctr)
		if newCtrPrefix <= sesskey.rcvctr.prefix:
			logger.error('CTR must increase (old %r, new %r)',
					sesskey.rcvctr.prefix, newCtrPrefix)
			raise InvalidParameterError

		sesskey.rcvctr.prefix = newCtrPrefix

		logger.debug('handle: enc={0!r} mac={1!r} ctr={2!r}' \
				.format(sesskey.rcvenc, sesskey.rcvmac, sesskey.rcvctr))

		plaintextData = AESCTR(sesskey.rcvenc, sesskey.rcvctr) \
				.decrypt(msg.encmsg)

		if b'\0' in plaintextData:
			plaintext, tlvData = plaintextData.split(b'\0', 1)
			tlvs = proto.TLV.parse(tlvData)
		else:
			plaintext = plaintextData
			tlvs = []

		if msg.rkeyid == self.ourKeyid:
			self.rotateDHKeys()
		if msg.skeyid == self.theirKeyid:
			self.rotateYKeys(ECDH.parse_serialized_pubKey(msg.dhy))

		return plaintext, tlvs

	def smpSecret(self, secret, question=None, appdata=None):
		if self.smp is None:
			logger.debug('Creating SMPHandler')
			self.smp = SMPHandler(self)

		self.smp.gotSecret(secret, question=question, appdata=appdata)

	def smpHandle(self, tlv, appdata=None):
		if self.smp is None:
			logger.debug('Creating SMPHandler')
			self.smp = SMPHandler(self)
		self.smp.handle(tlv, appdata=appdata)

	def smpAbort(self, appdata=None):
		if self.smp is None:
			logger.debug('Creating SMPHandler')
			self.smp = SMPHandler(self)
		self.smp.abort(appdata=appdata)

	def createDataMessage(self, message, flags=0, tlvs=None):
		# check MSGSTATE
		if self.theirKeyid == 0:
			raise InvalidParameterError

		if tlvs is None:
			tlvs = []

		sess = self.sessionkeys[1][0]
		sess.sendctr.inc()

		logger.debug('create: enc={0!r} mac={1!r} ctr={2!r}' \
				.format(sess.sendenc, sess.sendmac, sess.sendctr))

		# plaintext + TLVS
		plainBuf = message + b'\0' + b''.join([ bytes(t) for t in tlvs])
		encmsg = AESCTR(sess.sendenc, sess.sendctr).encrypt(plainBuf)

		msg = proto.DataMessage(flags, self.ourKeyid-1, self.theirKeyid,
				self.ourDHKey.get_serialized_pubKey(), sess.sendctr.byteprefix(),
				encmsg, b'', b''.join(self.savedMacKeys))

		self.savedMacKeys = []

		msg.mac = SHA1HMAC(sess.sendmac, msg.getMacedData())
		return msg

	def saneKeyIds(self, msg):
		anyzero = self.theirKeyid == 0 or msg.skeyid == 0 or msg.rkeyid == 0
		if anyzero or (msg.skeyid != self.theirKeyid and \
				msg.skeyid != self.theirKeyid - 1) or \
				(msg.rkeyid != self.ourKeyid and msg.rkeyid != self.ourKeyid - 1):
			return False
		if self.theirOldY is None and msg.skeyid == self.theirKeyid - 1:
			return False
		return True

	def startAKE(self, appdata=None):
		self.ake = AuthKeyExchange(self.ctx.user.getPrivkey(), self.goEncrypted)
		outMsg = self.ake.startAKE()
		self.ctx.sendInternal(outMsg, appdata=appdata)

	def handleAKE(self, inMsg, appdata=None):
		outMsg = None

		if not self.ctx.getPolicy('ALLOW_V2'):
			return

		if isinstance(inMsg, proto.DHCommit):
			if self.ake is None or self.ake.state != STATE_AWAITING_REVEALSIG:
				self.ake = AuthKeyExchange(self.ctx.user.getPrivkey(),
						self.goEncrypted)
			outMsg = self.ake.handleDHCommit(inMsg)

		elif isinstance(inMsg, proto.DHKey):
			if self.ake is None:
				return # ignore
			outMsg = self.ake.handleDHKey(inMsg)

		elif isinstance(inMsg, proto.RevealSig):
			if self.ake is None:
				return # ignore
			outMsg = self.ake.handleRevealSig(inMsg)

		elif isinstance(inMsg, proto.Signature):
			if self.ake is None:
				return # ignore
			self.ake.handleSignature(inMsg)

		if outMsg is not None:
			self.ctx.sendInternal(outMsg, appdata=appdata)

	def goEncrypted(self, ake):
		
		if ake.dh.pub == ake.gy:
			logger.warning('We are receiving our own messages')
			raise InvalidParameterError

		self.theirPubkey = ake.theirPubkey
		
		self.sessionId = ake.sessionId
		self.sessionIdHalf = ake.sessionIdHalf
		self.theirKeyid = ake.theirKeyid
		self.ourKeyid = ake.ourKeyid
		self.theirY = ake.gy
		self.theirOldY = None
		self.extraKey = ake.extraKey

		if self.ourKeyid != ake.ourKeyid + 1 or self.ourOldDHKey != ake.dh.pub:
			self.ourDHKey = ake.dh
			self.sessionkeys[0][0] = DHSession.create(self.ourDHKey, self.theirY)
			self.rotateDHKeys()

		# we don't need the AKE anymore, free the reference
		self.ake = None

		self.ctx._wentEncrypted()
		logger.info('went encrypted with {0}'.format(self.theirPubkey))

	def finished(self):
		self.smp = None

class AuthKeyExchange(object):

	def __init__(self, privkey, onSuccess):
		self.privkey = privkey
		self.state = STATE_NONE
		self.r = None
		self.encgx = None
		self.hashgx = None
		self.ourKeyid = 1
		self.theirPubkey = None
		self.theirKeyid = 1
		self.enc_c = None
		self.enc_cp = None
		self.mac_m1 = None
		self.mac_m1p = None
		self.mac_m2 = None
		self.mac_m2p = None
		self.sessionId = None
		self.sessionIdHalf = False
		self.dh = ECDH()
		self.onSuccess = onSuccess
		self.gy = None
		self.extraKey = None
		self.lastmsg = None

	def startAKE(self):
	
		self.r = long_to_bytes(random.getrandbits(128), 16)

		gxmpi = self.dh.get_serialized_pubKey()

		self.hashgx = SHA256(gxmpi)
		self.encgx = AESCTR(self.r).encrypt(gxmpi)

		self.state = STATE_AWAITING_DHKEY

		return proto.DHCommit(self.encgx, self.hashgx)

	def handleDHCommit(self, msg):
		self.encgx = msg.encgx
		self.hashgx = msg.hashgx

		self.state = STATE_AWAITING_REVEALSIG
		return proto.DHKey(self.dh.get_serialized_pubKey())

	# Une fois g^y reçu, on calcule Xb
	def handleDHKey(self, msg):
	
		if self.state == STATE_AWAITING_DHKEY:
			self.gy = ECDH.parse_serialized_pubKey(msg.gy)

			self.createAuthKeys()

			# Calcul de Xb et usage des clés ECDSA
			aesxb = self.calculatePubkeyAuth(self.enc_c, self.mac_m1)

			self.state = STATE_AWAITING_SIG

			self.lastmsg = proto.RevealSig(self.r, aesxb, b'')
			self.lastmsg.mac = SHA256HMAC160(self.mac_m2,
					self.lastmsg.getMacedData())
			return self.lastmsg

		elif self.state == STATE_AWAITING_SIG:
			logger.info('received DHKey while not awaiting DHKEY')
			if msg.gy == self.gy: # TOCHANGE (Inutile pour le moment)
				logger.info('resending revealsig')
				return self.lastmsg
		else:
			logger.info('bad state for DHKey')

	def handleRevealSig(self, msg):
		if self.state != STATE_AWAITING_REVEALSIG:
			logger.error('bad state for RevealSig')
			raise InvalidParameterError

		self.r = msg.rkey
		gxmpi = AESCTR(self.r).decrypt(self.encgx)
		if SHA256(gxmpi) != self.hashgx:
			logger.error('Hashes don\'t match')
			logger.info('r=%r, hashgx=%r, computed hash=%r, gxmpi=%r',
					self.r, self.hashgx, SHA256(gxmpi), gxmpi)
			raise InvalidParameterError

		self.gy = ECDH.parse_serialized_pubKey(gxmpi)
		self.createAuthKeys()

		if msg.mac != SHA256HMAC160(self.mac_m2, msg.getMacedData()):
			logger.error('HMACs don\'t match')
			logger.info('mac=%r, mac_m2=%r, data=%r', msg.mac, self.mac_m2,
					msg.getMacedData())
			raise InvalidParameterError

		self.checkPubkeyAuth(self.enc_c, self.mac_m1, msg.encsig)

		aesxb = self.calculatePubkeyAuth(self.enc_cp, self.mac_m1p)
		self.sessionIdHalf = True

		self.onSuccess(self)

		self.ourKeyid = 0
		self.state = STATE_NONE

		cmpmac = struct.pack(b'!I', len(aesxb)) + aesxb

		return proto.Signature(aesxb, SHA256HMAC160(self.mac_m2p, cmpmac))

	def handleSignature(self, msg):
		if self.state != STATE_AWAITING_SIG:
			logger.error('bad state (%d) for Signature', self.state)
			raise InvalidParameterError

		if msg.mac != SHA256HMAC160(self.mac_m2p, msg.getMacedData()):
			logger.error('HMACs don\'t match')
			raise InvalidParameterError

		self.checkPubkeyAuth(self.enc_cp, self.mac_m1p, msg.encsig)

		self.sessionIdHalf = False

		self.onSuccess(self)

		self.ourKeyid = 0
		self.state = STATE_NONE

	def createAuthKeys(self):
		
		s = self.dh.get_shared_secret(self.gy)
		sbyte = pack_mpi(s)
		self.sessionId = SHA256(b'\x00' + sbyte)[:8]
		enc = SHA256(b'\x01' + sbyte)
		self.enc_c = enc[:16]
		self.enc_cp = enc[16:]
		self.mac_m1 = SHA256(b'\x02' + sbyte)
		self.mac_m2 = SHA256(b'\x03' + sbyte)
		self.mac_m1p = SHA256(b'\x04' + sbyte)
		self.mac_m2p = SHA256(b'\x05' + sbyte)
		self.extraKey = SHA256(b'\xff' + sbyte)

	# Génération de AES(Xb) 
	def calculatePubkeyAuth(self, key, mackey):

		pubkey = self.privkey.serializePublicKey()
		buf = self.dh.get_serialized_pubKey()
		buf += ECDH.serialize_pubKey(self.gy)
		buf += pubkey
		buf += struct.pack(b'!I', self.ourKeyid)
		MBsigned = self.privkey.sign(SHA256HMAC(mackey, buf))
	
		logging.debug("Signature : {}".format( ':'.join(x.encode('hex') for x in MBsigned) ))
		
		buf = pubkey
		buf += struct.pack(b'!I', self.ourKeyid)
		buf += MBsigned
		
		logging.debug("Données envoyées : {}".format( ':'.join(x.encode('hex') for x in buf) ))
		
		return AESCTR(key).encrypt(buf)

	# Vérification de AES(Xb) 
	def checkPubkeyAuth(self, key, mackey, encsig):
		
		auth = AESCTR(key).decrypt(encsig)
		
		logging.debug("Données reçues : {}".format( ':'.join(x.encode('hex') for x in auth) ))
		
		self.theirPubkey, auth = PK.parsePublicKey(auth)
		
		logging.debug("Clé parsée {}".format( ':'.join(x.encode('hex') for x in self.theirPubkey.serializePublicKey()) ))
		
		receivedKeyid, auth = proto.unpack(b'!I', auth)
		if receivedKeyid == 0:
			raise InvalidParameterError
			
		logging.debug("Signature reçue {}".format( ':'.join(x.encode('hex') for x in auth) ))

		authbuf = ECDH.serialize_pubKey(self.gy)
		authbuf += self.dh.get_serialized_pubKey()
		authbuf += self.theirPubkey.serializePublicKey()
		authbuf += struct.pack(b'!I', receivedKeyid)

		if self.theirPubkey.verify(SHA256HMAC(mackey, authbuf), auth) is False:
			raise InvalidParameterError
		self.theirKeyid = receivedKeyid

SMPPROG_OK = 0
SMPPROG_CHEATED = -2
SMPPROG_FAILED = -1
SMPPROG_SUCCEEDED = 1

class SMPHandler:
	def __init__(self, crypto):
		self.crypto = crypto
		self.state = 1
		self.g1 = DH_GENERATOR
		self.g2 = None
		self.g3 = None
		self.g3o = None
		self.x2 = None
		self.x3 = None
		self.prog = SMPPROG_OK
		self.pab = None
		self.qab = None
		self.questionReceived = False
		self.secret = None
		self.p = None
		self.q = None

	def abort(self, appdata=None):
		self.state = 1
		self.sendTLV(proto.SMPABORTTLV(), appdata=appdata)

	def sendTLV(self, tlv, appdata=None):
		self.crypto.ctx.sendInternal(b'', tlvs=[tlv], appdata=appdata)

	def handle(self, tlv, appdata=None):
		logger.debug('handling TLV {0.__class__.__name__}'.format(tlv))
		self.prog = SMPPROG_CHEATED
		if isinstance(tlv, proto.SMPABORTTLV):
			self.state = 1
			return
		is1qTlv = isinstance(tlv, proto.SMP1QTLV)
		if isinstance(tlv, proto.SMP1TLV) or is1qTlv:
			if self.state != 1:
				self.abort(appdata=appdata)
				return

			msg = tlv.mpis

			if not check_group(msg[0]) or not check_group(msg[3]) \
					or not check_exp(msg[2]) or not check_exp(msg[5]) \
					or not check_known_log(msg[1], msg[2], self.g1, msg[0], 1) \
					or not check_known_log(msg[4], msg[5], self.g1, msg[3], 2):
				logger.error('invalid SMP1TLV received')
				self.abort(appdata=appdata)
				return

			self.questionReceived = is1qTlv

			self.g3o = msg[3]

			self.x2 = random.randrange(2, DH_MAX)
			self.x3 = random.randrange(2, DH_MAX)

			self.g2 = pow(msg[0], self.x2, DH_MODULUS)
			self.g3 = pow(msg[3], self.x3, DH_MODULUS)

			self.prog = SMPPROG_OK
			self.state = 0
			return
		if isinstance(tlv, proto.SMP2TLV):
			if self.state != 2:
				self.abort(appdata=appdata)
				return

			msg = tlv.mpis
			mp = msg[6]
			mq = msg[7]

			if not check_group(msg[0]) or not check_group(msg[3]) \
					or not check_group(msg[6]) or not check_group(msg[7]) \
					or not check_exp(msg[2]) or not check_exp(msg[5]) \
					or not check_exp(msg[9]) or not check_exp(msg[10]) \
					or not check_known_log(msg[1], msg[2], self.g1, msg[0], 3) \
					or not check_known_log(msg[4], msg[5], self.g1, msg[3], 4):
				logger.error('invalid SMP2TLV received')
				self.abort(appdata=appdata)
				return

			self.g3o = msg[3]
			self.g2 = pow(msg[0], self.x2, DH_MODULUS)
			self.g3 = pow(msg[3], self.x3, DH_MODULUS)

			if not self.check_equal_coords(msg[6:11], 5):
				logger.error('invalid SMP2TLV received')
				self.abort(appdata=appdata)
				return

			r = random.randrange(2, DH_MAX)
			self.p = pow(self.g3, r, DH_MODULUS)
			msg = [self.p]
			qa1 = pow(self.g1, r, DH_MODULUS)
			qa2 = pow(self.g2, self.secret, DH_MODULUS)
			self.q = qa1*qa2 % DH_MODULUS
			msg.append(self.q)
			msg += self.proof_equal_coords(r, 6)

			inv = invMod(mp)
			self.pab = self.p * inv % DH_MODULUS
			inv = invMod(mq)
			self.qab = self.q * inv % DH_MODULUS

			msg.append(pow(self.qab, self.x3, DH_MODULUS))
			msg += self.proof_equal_logs(7)

			self.state = 4
			self.prog = SMPPROG_OK
			self.sendTLV(proto.SMP3TLV(msg), appdata=appdata)
			return
		if isinstance(tlv, proto.SMP3TLV):
			if self.state != 3:
				self.abort(appdata=appdata)
				return

			msg = tlv.mpis

			if not check_group(msg[0]) or not check_group(msg[1]) \
					or not check_group(msg[5]) or not check_exp(msg[3]) \
					or not check_exp(msg[4]) or not check_exp(msg[7]) \
					or not self.check_equal_coords(msg[:5], 6):
				logger.error('invalid SMP3TLV received')
				self.abort(appdata=appdata)
				return

			inv = invMod(self.p)
			self.pab = msg[0] * inv % DH_MODULUS
			inv = invMod(self.q)
			self.qab = msg[1] * inv % DH_MODULUS

			if not self.check_equal_logs(msg[5:8], 7):
				logger.error('invalid SMP3TLV received')
				self.abort(appdata=appdata)
				return

			md = msg[5]
			msg = [pow(self.qab, self.x3, DH_MODULUS)]
			msg += self.proof_equal_logs(8)

			rab = pow(md, self.x3, DH_MODULUS)
			self.prog = SMPPROG_SUCCEEDED if self.pab == rab else SMPPROG_FAILED

			if self.prog != SMPPROG_SUCCEEDED:
				logger.error('secrets don\'t match')
				self.abort(appdata=appdata)
				self.crypto.ctx.setCurrentTrust('')
				return

			logger.info('secrets matched')
			if not self.questionReceived:
				self.crypto.ctx.setCurrentTrust('smp')
			self.state = 1
			self.sendTLV(proto.SMP4TLV(msg), appdata=appdata)
			return
		if isinstance(tlv, proto.SMP4TLV):
			if self.state != 4:
				self.abort(appdata=appdata)
				return

			msg = tlv.mpis

			if not check_group(msg[0]) or not check_exp(msg[2]) \
					or not self.check_equal_logs(msg[:3], 8):
				logger.error('invalid SMP4TLV received')
				self.abort(appdata=appdata)
				return

			rab = pow(msg[0], self.x3, DH_MODULUS)

			self.prog = SMPPROG_SUCCEEDED if self.pab == rab else SMPPROG_FAILED

			if self.prog != SMPPROG_SUCCEEDED:
				logger.error('secrets don\'t match')
				self.abort(appdata=appdata)
				self.crypto.ctx.setCurrentTrust('')
				return

			logger.info('secrets matched')
			self.crypto.ctx.setCurrentTrust('smp')
			self.state = 1
			return

	def gotSecret(self, secret, question=None, appdata=None):
		ourFP = self.crypto.ctx.user.getPrivkey().fingerprint()
		if self.state == 1:
			# first secret -> SMP1TLV
			combSecret = SHA256(b'\1' + ourFP +
					self.crypto.theirPubkey.fingerprint() +
					self.crypto.sessionId + secret)

			self.secret = bytes_to_long(combSecret)

			self.x2 = random.randrange(2, DH_MAX)
			self.x3 = random.randrange(2, DH_MAX)

			msg = [pow(self.g1, self.x2, DH_MODULUS)]
			msg += proof_known_log(self.g1, self.x2, 1)
			msg.append(pow(self.g1, self.x3, DH_MODULUS))
			msg += proof_known_log(self.g1, self.x3, 2)

			self.prog = SMPPROG_OK
			self.state = 2
			if question is None:
				self.sendTLV(proto.SMP1TLV(msg), appdata=appdata)
			else:
				self.sendTLV(proto.SMP1QTLV(question, msg), appdata=appdata)
		if self.state == 0:
			# response secret -> SMP2TLV
			combSecret = SHA256(b'\1' + self.crypto.theirPubkey.fingerprint() +
					ourFP + self.crypto.sessionId + secret)

			self.secret = bytes_to_long(combSecret)

			msg = [pow(self.g1, self.x2, DH_MODULUS)]
			msg += proof_known_log(self.g1, self.x2, 3)
			msg.append(pow(self.g1, self.x3, DH_MODULUS))
			msg += proof_known_log(self.g1, self.x3, 4)

			r = random.randrange(2, DH_MAX)

			self.p = pow(self.g3, r, DH_MODULUS)
			msg.append(self.p)

			qb1 = pow(self.g1, r, DH_MODULUS)
			qb2 = pow(self.g2, self.secret, DH_MODULUS)
			self.q = qb1 * qb2 % DH_MODULUS
			msg.append(self.q)

			msg += self.proof_equal_coords(r, 5)

			self.state = 3
			self.sendTLV(proto.SMP2TLV(msg), appdata=appdata)

	def proof_equal_coords(self, r, v):
		r1 = random.randrange(2, DH_MAX)
		r2 = random.randrange(2, DH_MAX)
		temp2 = pow(self.g1, r1, DH_MODULUS) \
				* pow(self.g2, r2, DH_MODULUS) % DH_MODULUS
		temp1 = pow(self.g3, r1, DH_MODULUS)

		cb = SHA256(struct.pack(b'B', v) + pack_mpi(temp1) + pack_mpi(temp2))
		c = bytes_to_long(cb)

		temp1 = r * c % SM_ORDER
		d1 = (r1-temp1) % SM_ORDER

		temp1 = self.secret * c % SM_ORDER
		d2 = (r2 - temp1) % SM_ORDER
		return c, d1, d2

	def check_equal_coords(self, coords, v):
		(p, q, c, d1, d2) = coords
		temp1 = pow(self.g3, d1, DH_MODULUS) * pow(p, c, DH_MODULUS) \
				% DH_MODULUS

		temp2 = pow(self.g1, d1, DH_MODULUS) \
				* pow(self.g2, d2, DH_MODULUS) \
				* pow(q, c, DH_MODULUS) % DH_MODULUS

		cprime = SHA256(struct.pack(b'B', v) + pack_mpi(temp1) + pack_mpi(temp2))

		return long_to_bytes(c, 32) == cprime

	def proof_equal_logs(self, v):
		r = random.randrange(2, DH_MAX)
		temp1 = pow(self.g1, r, DH_MODULUS)
		temp2 = pow(self.qab, r, DH_MODULUS)

		cb = SHA256(struct.pack(b'B', v) + pack_mpi(temp1) + pack_mpi(temp2))
		c = bytes_to_long(cb)
		temp1 = self.x3 * c % SM_ORDER
		d = (r - temp1) % SM_ORDER
		return c, d

	def check_equal_logs(self, logs, v):
		(r, c, d) = logs
		temp1 = pow(self.g1, d, DH_MODULUS) \
				* pow(self.g3o, c, DH_MODULUS) % DH_MODULUS

		temp2 = pow(self.qab, d, DH_MODULUS) \
				* pow(r, c, DH_MODULUS) % DH_MODULUS

		cprime = SHA256(struct.pack(b'B', v) + pack_mpi(temp1) + pack_mpi(temp2))
		return long_to_bytes(c, 32) == cprime

def proof_known_log(g, x, v):
	r = random.randrange(2, DH_MAX)
	c = bytes_to_long(SHA256(struct.pack(b'B', v) + pack_mpi(pow(g, r, DH_MODULUS))))
	temp = x * c % SM_ORDER
	return c, (r-temp) % SM_ORDER

def check_known_log(c, d, g, x, v):
	gd = pow(g, d, DH_MODULUS)
	xc = pow(x, c, DH_MODULUS)
	gdxc = gd * xc % DH_MODULUS
	return SHA256(struct.pack(b'B', v) + pack_mpi(gdxc)) == long_to_bytes(c, 32)

def invMod(n):
	return pow(n, DH_MODULUS_2, DH_MODULUS)

class InvalidParameterError(RuntimeError):
	pass
