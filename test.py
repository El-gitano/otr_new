import potr, time, os

DEFAULT_POLICY_FLAGS = {
	'ALLOW_V1':False,
	'ALLOW_V2':True,
	'REQUIRE_ENCRYPTION':True,
	'SEND_TAG':True,
}

PROTOCOL='xmpp'
MMS=1024

class MyContext(potr.context.Context):

	def __init__(self, account, peer):
		super(MyContext, self).__init__(account, peer)

	# this method has should return True or False for a variety of policies.
	# to start off, 'ALLOW_V1', 'ALLOW_V2', and 'REQUIRE_ENCRYPTION' seemed like the minimum
	def getPolicy(self, key):
		if key in DEFAULT_POLICY_FLAGS:
			return DEFAULT_POLICY_FLAGS[key]
		else:
			return False

	def inject(self, msg, appdata=None):
		print msg
		# this method is called when potr needs to inject a message into the stream.	for instance, upon receiving an initiating stanza, potr will inject the key exchange messages
		# here is where you should hook into your app and actually send the message potr gives you

	def setState(self, newstate):
		# overriding this method is not strictly necessary, but this is a good place to hook state changes for notifying your app, to give your user feedback.
		# I used this method to set icon state and insert a message into chat history, notifying the user that encryption is or is not enabled.
		# Don't forget to call the base class method
		print "Le context a change"
		super(MyContext, self).setState(newstate)
		
class MyAccount(potr.context.Account):

	def __init__(self, jid):
		super(MyAccount, self).__init__(jid, PROTOCOL, MMS)

	# this method needs to be overwritten to load the private key
	# it should return None in the event that no private key is found
	# returning None will trigger autogenerating a private key in the default implementation
	def loadPrivkey(self):
		return os.urandom(16)

	# this method needs to be overwritten to save the private key
	def savePrivkey(self):
		pass

account = MyAccount('test')
account2 = MyAccount('test2')
context1 = MyContext(account, 'test2')
context2 = MyContext(account2, 'test')

msg1 = context1.sendMessage(0, 'test')
context2.receiveMessage(msg1)
