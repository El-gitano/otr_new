#!/usr/bin/python
# -*-coding:Utf-8 -*

import potr, socket, select, sys, argparse, re
import logging

MMS = 4096
EXIT_SUCCESS = 0
EXIT_ERROR = 1

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
		return True

	def inject(self, msg, appdata=None):
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
		if line is not None:
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
						sys.exit(EXIT_SUCCESS)
					else :
						clear = self.context.receiveMessage(data)[0]
						self.print_line(clear)
				 
				# Message entré au clavier
				else :
					msg = sys.stdin.readline()
			
					if msg == 'quit\n':
						print 'Disconnecting'
						self.socket.close()
						sys.exit(EXIT_SUCCESS)
			
					self.socket.send(self.context.sendMessage(1, msg))
					self.prompt()
					
class Client(Chatter):

	def __init__(self, ip, port):
		
		if ip is None or port is None:
			raise ValueError("Erreur dans la spécification des paramètres")
			
		super(Client, self).__init__()
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.settimeout(2)
		
		self._ip = ip
		self._port = port

	def start(self):
	
		# Connexion
		try :
			self.socket.connect((self._ip, self._port))
		except :
			print 'Unable to connect'
			sys.exit(EXIT_ERROR)
		 
		print 'Connected to remote ip. Start sending messages'
		
		self.context.socket = self.socket
		self.socket.send('?OTRv2?')
		
		self.handle_socket()
			
class Server(Chatter):

	def __init__(self, port):
	
		if port is None:
			raise ValueError("Erreur dans la spécification des paramètres")
			
		super(Server, self).__init__()
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.s.bind(('', port))
		self.s.listen(1)
	
	def start(self):

		self.socket, x = self.s.accept()
		print "Client connected. Start sending messages"
		self.context.socket = self.socket
		
		self.handle_socket()

# Main
if __name__ == "__main__":

	# Définition du parser d'arguments
	parser = argparse.ArgumentParser()
	
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-c", "--connect", dest="IP", nargs=1, help="Établit une connexion à l'adresse IP spécifiée en paramètre")
	group.add_argument("-l", "--listen", help="Met en écoute le client sur le port spécifié en paramètre", action="store_true")
	
	parser.add_argument("port", type=int, help="Le port sur lequel écouter/se connecter")
	
	# Récupération des arguments
	args = parser.parse_args()

	port = args.port
	if port < 0 or port > 65535:
		print "Erreur dans la valeur du port spécifié"
		sys.exit(EXIT_ERROR)
	
	impl = None
	logFile = None
	
	# Serveur
	if args.listen == True:
    
		impl = Server(port)
		logFile = './logsServer.log'
    
    # Client	
   	elif args.IP is not None and len(args.IP) == 1:
   	
   		ip = args.IP[0]
   		if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
			print "Erreur dans le format de l'adresse IP"
			sys.exit(EXIT_ERROR)
		
   		impl = Client(ip, port)
   		logFile = './logsClient.log'
   	
   	else:
   		print "Erreur dans les paramètres spécifiés"
   		sys.exit(EXIT_ERROR)
   		
   	# Démarrage du programme
	logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(levelname)s %(message)s',
                filename=logFile,
                filemode='w')
		
	impl.start()
