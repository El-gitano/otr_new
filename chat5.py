#!/usr/bin/python
# -*-coding:Utf-8 -*

import potr, socket, select, sys

MMS = 4096

class MyAccount(potr.context.Account):
	
	def __init__(self, jid):
		super(MyAccount, self).__init__(jid, 'xmpp', MMS)
		self.jid = jid

	def loadPrivkey(self):
		return None

	def savePrivkey(self):
		pass

class MyContext(potr.context.Context):

	def __init__(self, account, peer):
		super(MyContext, self).__init__(account, peer)
		self.socket = None

	def getPolicy(self, key):
		return True # TODO

	def inject(self, msg, appdata=None):
		print "From {} to {} : {}".format(self.user.jid, self.peer.jid, msg)
		self.socket.send(msg)

	def setState(self, newstate):
		p_selfstate = "None"
		if(self.state == potr.context.STATE_PLAINTEXT):
			p_selfstate = "STATE_PLAINTEXT"
		elif(self.state == potr.context.STATE_ENCRYPTED):
			p_selfstate = "STATE_ENCRYPTED"
		elif(self.state == potr.context.STATE_FINISHED):
			p_selfstate = "STATE_FINISHED"

		p_newstate = "None"
		if(newstate == potr.context.STATE_PLAINTEXT):
			p_newstate = "STATE_PLAINTEXT"
		elif(newstate == potr.context.STATE_ENCRYPTED):
			p_newstate = "STATE_ENCRYPTED"
		elif(newstate == potr.context.STATE_FINISHED):
			p_newstate = "STATE_FINISHED"

		print "{} : {} -> {}".format(self.user.name, p_selfstate, p_newstate)
		super(MyContext, self).setState(newstate)

class Chatter(object):

	def __init__(self):
	
		self.socket = None
		
		self.account = MyAccount('me')
		self.context = MyContext(self.account, MyAccount('other'))
		
	def prompt(self):
		sys.stdout.write('>> ')
		sys.stdout.flush()
	
	def print_line(self, line):
		sys.stdout.write('\r{}'.format(line))
		self.prompt()
			
	def handle_socket(self):
		
		socket_list = [sys.stdin, self.socket]
		self.prompt()
		
		while True:	 
		
			# Récupération de la liste des socket dispo en lecture
			read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
			 
			for sock in read_sockets:
				
				# Message reçu
				if sock == self.socket:
					data = sock.recv(MMS)
					if not data :
						print '\nDisconnected'
						self.socket.close()
						sys.exit()
					else :
						clear = self.context.receiveMessage(data)[0]
						self.print_line(clear)
				 
				# Message entré au clavier
				else :
					msg = sys.stdin.readline()
			
					if msg == 'quit\n':
						print 'Disconnecting'
						self.socket.close()
						sys.exit()
			
					self.socket.send(self.context.sendMessage(1, msg))
					self.prompt()
					
class Client(Chatter):

	def __init__(self, host, port):
		
		super(Client, self).__init__()
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.settimeout(2)

	def start(self):
	
		# Connexion
		try :
			self.socket.connect((host, port))
		except :
			print 'Unable to connect'
			sys.exit()
		 
		print 'Connected to remote host. Start sending messages'
		
		self.context.socket = self.socket
		self.socket.send('?OTRv2?')
		
		self.handle_socket()
			
class Server(Chatter):

	def __init__(self, port):
	
		super(Server, self).__init__()
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.s.bind(('', port))
		self.s.listen(1)
	
	def start(self):

		self.socket, x = self.s.accept()
		self.context.socket = self.socket
		
		self.handle_socket()

# Main
if __name__ == "__main__":
	 
	if(len(sys.argv) < 3) :
		print 'Usage : python chat3.py hostname port'
		sys.exit()
	 
	host = sys.argv[1]
	port = int(sys.argv[2])
	
	if host.lower() == 'listen':
		Server(port).start()
	
	else:
		Client(host, port).start()
