#!/usr/bin/python
# -*-coding:Utf-8 -*

from potr.compatcrypto import ECDH

print 'Début des tests sur ECDH'

for i in range(100):

	ecdhAlice = ECDH()
	ecdhBob = ECDH()

	commonAlice = ecdhAlice.get_shared_secret(ecdhBob.pub)
	commonBob = ecdhBob.get_shared_secret(ecdhAlice.pub)

	assert commonAlice == commonBob, (commonAlice, commonBob)

print 'Tests ECDH OK !'
