#!/usr/bin/python3
# -*-coding:Utf-8 -*

import logging
from sleekxmpp import ClientXMPP


class OtrClient(ClientXMPP):

	def __init__(self, jid, password):
		
		ClientXMPP.__init__(self, jid, password)
		self.add_event_handler("session_start", self.session_start)
        
	def session_start(self, event):
	
		print('Connected')
		self.disconnect()
        
if __name__ == '__main__':

	# TODO Utiliser argparse

	logging.basicConfig(level=logging.ERROR, format='%(levelname)-8s %(message)s')

	jid = input('JID : ')
	password = input("Password : ")
	xmpp = OtrClient(jid, password)
	xmpp.connect()
	xmpp.process(block=True)
	print('Fin du prog')
