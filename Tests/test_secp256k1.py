#!/usr/bin/python
# -*-coding:Utf-8 -*

from binascii import hexlify, unhexlify
import random

CURVE_NAME = 'secp256k1'

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

print 'Début des tests sur l\'implémentation de la courbe elliptique {}'.format(CURVE_NAME)

curve = EllipticCurve(CURVE_NAME, p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, a=0, b=7,	g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8), n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, h=1)

# Test vecteurs hxBitcoin
with open('./secp256k1/k.txt') as f_k:
	with open('./secp256k1/x.txt') as f_x:
		with open('./secp256k1/y.txt') as f_y:
			for line in f_k:
   			
				k = int(line.rstrip())
				res_point = curve.scalar_mult(k, curve.g)
				
				x_coord = int(f_x.readline().rstrip(), 16)
				y_coord = int(f_y.readline().rstrip(), 16)
				ref_point = (x_coord, y_coord)

				assert (res_point == ref_point), (k, res_point, ref_point)

# Test vecteurs 2				
with open('./secp256k1/m.txt') as f_k:
	with open('./secp256k1/x2.txt') as f_x:
		with open('./secp256k1/y2.txt') as f_y:
			for line in f_k:
   			
				k = int(line.rstrip(), 16)
				res_point = curve.scalar_mult(k, curve.g)
				
				x_coord = int(f_x.readline().rstrip(), 16)
				y_coord = int(f_y.readline().rstrip(), 16)
				ref_point = (x_coord, y_coord)

				assert (res_point == ref_point), (k, res_point, ref_point)

# Test du point d'infinité
assert (curve.scalar_mult(curve.n, curve.g) is None)

# Tests aléatoires
for i in range(100):

	a = random.randrange(1, curve.n)
	b = random.randrange(1, curve.n)
	c = a+b
	
	p = curve.scalar_mult(a, curve.g)
	q = curve.scalar_mult(b, curve.g)
	r = curve.scalar_mult(c, curve.g)
	
	assert (curve.point_add(p, q) == curve.point_add(q, p) == r), (a, b)
	
print "Tests de l'implémentation de la courbe elliptique {} OK !".format(CURVE_NAME)
