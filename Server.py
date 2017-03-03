import socket, sys
import time, re
import thread
import uuid
import pyDH
import os
#For Message digest and hashing algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
#Importing packages required for importing key files
from cryptography.hazmat.primitives import serialization
#Importing packages for signing private key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
#Importing packages for retrieving key and initialization vector
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

global inp_file, sender_private_key, recvr_private_key,encrypted_final_file,output_plaintext_file



#Send message from Server to client
def sendmsgfromserver ():	
	#print client_list
	for index in range(len(client_list)) :
		global data
		#print "data before encoding" + str(data)
		#performing encoding operation before sending to client
		data=encodetext_Toclient(data)
		#print "data after encoding" + str(data)
		s.sendto(data,client_list[index])

#Sending data username and password details 
def send_dataTo_client(reply):
	#print "Executing send data to client function"
	#print reply
	#print addr
	#performing encoding operation before sending to client
	s.sendto(reply , addr)

#Checking replay attack	
def check_replayattack(timestamp):
	current_timestamp=time.time()
	if (int(timestamp)+5) > current_timestamp:
		#print "Server side: Its Secure, No replayattack is ON"
		pass
	else :
		print "Server side: Alert: Replayattack is performed Fix it"

#Rece data like username and password		
def receive_dataFrom_client():
	#print "executing receive data from client"
	global s,data,addr
	#print addr
	rdata = s.recvfrom(4096)
	#print rdata
	data = rdata[0]
	addr = rdata[1]

#Writing online user list to a file
def onlineUsers(username,address):
	f = open('online_userslist.txt','w')
	f.write(str(username+'+'))
	f.write(str(address))
	f.close()

#Checking the logged user authentication status	
def checkUser(logged_user):
	global Online_USERLIST
	#print "Entering check user function"
	current_timestamp=time.time()
	#sending Salt Time
	#reply = str(users_list[users_list.index(logged_user)+2]) + '&&&' + str(current_timestamp)
	reply = str(users_list[users_list.index(logged_user)]) + '&&&' + str(current_timestamp)
	#print reply
	send_dataTo_client(reply)
	
	#Receiving #sending User+Passsalt+time+dhkey
	receive_dataFrom_client()
	m =  re.split(r'&&&',data)
	#print m
	m[2]=int(float(m[2]))
	
	#checking replay attack
	check_replayattack(str(m[2]))
	#print m[1]
	#print users_list.index(logged_user)
	#print users_list[users_list.index(logged_user)
	if m[1] == users_list[users_list.index(logged_user)]:
		print "New User  " + logged_user + "  logged in"
		Online_USERLIST = []
		Online_USERLIST.append(logged_user)
		onlineUsers(logged_user,addr)
		reply=str("Welcome" + ' ' + logged_user)
		symkey=(int(m[3]))^3
		print "-------------------------------------------"
		#print symkey
		send_dataTo_client(reply)		
		#getting current timestamp
		current_timestamp=time.time()
		#creating DiffiHellman key for Server
		DiffiHellman_key=generateDiffieHellamanKeys()
		#DiffiHellman_key=g^2 % p
		#sending dhclientkey
		reply= str(DiffiHellman_key)+'&&&'+str(current_timestamp)
		send_dataTo_client(reply)
		return "Success"

	else:
		print "invalid password entered"
		reply = str("invalid password please enter your password again")
		send_dataTo_client(reply)
		return "Failure"

#Generating Diffie-Hellman keys		
def generateDiffieHellamanKeys():
	d1 = pyDH.DiffieHellman(16) # Uses 4096 bit key
	d1_pubkey = d1.gen_public_key() # d1_pubkey is g^c mod p
	return d1_pubkey

def encodetext_Toclient (data_msg):
	#print "Encoding operation started"
	#Importing key file which obtained through openssl
	with open(sender_private_key, "rb") as key_file:
		private_key_sender = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	public_key_sender = private_key_sender.public_key()
	
	with open(recvr_private_key, "rb") as key_file:
		private_key_receiver = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	public_key_receiver = private_key_receiver.public_key()
	
	#preparing hashing sha256
	signer = private_key_sender.signer(
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
	#Assiging value of text to the file called "bits"
	bits = data_msg
		
	#plain text converted to hash message
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(bits)
	hashed_msg=digest.finalize()
		
	#hashed message signed using sender private key
	signer.update(hashed_msg)
	signed_message_pkey = signer.finalize()
	
	#Adding message and hash
	msg_plus_hash= bits+'0123'+signed_message_pkey
	
	#Generating symmetric Key
	backend = default_backend()
	cbc_key = os.urandom(32) #return 32 random bytes suitable for cryptographic use
	cbc_iv = os.urandom(16) #return 16 random bytes suitable for cryptographic use
	
	#Padding
	pad_length=""
	bits=msg_plus_hash
	length = 16 - (len(bits) % 16)
	bits = bits+chr(97)*length
	if length<10: #To check two digit number appending 0 before it if not
		pad_length="0"+str(length)
	else:
		pad_length=str(length)
		
	#using CBC for Symetric encryption
	cbc_cipher = Cipher(algorithms.AES(cbc_key), modes.CBC(cbc_iv), backend=backend)
	cbc_encryptor = cbc_cipher.encryptor()
	cbc_ciphertext = cbc_encryptor.update(bits) + cbc_encryptor.finalize()
	
	pem = public_key_receiver.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
	
	message=cbc_key
	signed_ciphertext_public_key = public_key_receiver.encrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	#Write to file
	final_encrypted_out=cbc_ciphertext+"5678"+signed_ciphertext_public_key+pad_length+cbc_iv
	encrypted_data_msg = final_encrypted_out
	return encrypted_data_msg
	#f = open( encrypted_final_file, 'wb' )
	#f.write( final_encrypted_out )
	#print "Encrypted text file is created successfully"
	#f.close()

	
def decodetext_FromClient (text):
	#global encrypted_final_file
	#print "Decoding operation started"
	
	#Importing key file which obtained through openssl
	with open(sender_private_key, "rb") as key_file:
		private_key_sender = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	public_key_sender = private_key_sender.public_key()
	
	with open(recvr_private_key, "rb") as key_file:
		private_key_receiver = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	public_key_receiver = private_key_receiver.public_key()	
	
	#calling function to retreive all character files into variable byte
	bits = text
	
	#print "Input encrypted bits is stored as " + str(bits)
	
	#Extracting initialization vector and actual msg from retrieved message
	de_cbc_iv=bits[-16:]
	#print de_cbc_iv
	#obtaining after removing bits
	bits=bits[:-16]
	#print bits
	length=int(bits[-2:])
	bits=bits[:-2]
	
	#split message hash from key
	msg_plus_hash=bits.split('5678')[0]
	extracted_key=bits.split('5678')[1]

	#Decrypting with receiver private key
	plaintext = private_key_receiver.decrypt(
		extracted_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	backend = default_backend()
	de_cbc_key = plaintext
	
	#Decrypt message and hash with cbc decryption
	de_cipher_txt = Cipher(algorithms.AES(de_cbc_key), modes.CBC(de_cbc_iv), backend=backend)
	decryptor = de_cipher_txt.decryptor()
	decrypted_output=decryptor.update(msg_plus_hash) + decryptor.finalize()
	
	#splitting actual original message and signed hash message
	actual_msg = decrypted_output.split('0123')[0]
	extracted_signedhash= decrypted_output.split('0123')[1]
	#finally extracting signed hash from padded output length
	extracted_signedhash = extracted_signedhash[:-length]
	
	#Calculating hash from recovered message
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(actual_msg)
	hashed_message=digest.finalize()
	
	pem = public_key_sender.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	return actual_msg
	"""
	ofile = open( output_plaintext_file, 'w' )
	ofile.write( actual_msg+"\n" )
	try:
		os.stat("output_plaintext_file").st_size == 0
		print "Encrypted text is decrpyted and actual information is written to file successfully"
	except:
		print "Error: Problem with decryption of information"
	ofile.close
	"""
	

##Receive message from client to server		
def recvmsgfromclient ():
	while True:
		global data, s
		rdata = s.recvfrom(1024)
		addr = rdata[1]
		data = decodetext_FromClient(rdata[0])
		#print "Decoded data is " + str(data)
		if "LIST" in data:
			#print "entering list loop"
			data = "<============= PRINTING ONLINE USERS LIST ===============> " + '\n' + str(Online_USERLIST) + '\n'
			#print data
			if addr not in client_list:
				client_list.append(addr)
			sendmsgfromserver()
		elif "SEND" in data:
			#print data[5:]
			print "<- <" + "From " + str(addr[0])+":"+str(addr[1]) + ">: " + str(data[5:])
			data = "<- <" + "From " + str(addr[0])+":"+str(addr[1]) + ">: " + str(data[5:])
			if addr not in client_list:
				client_list.append(addr)
			sendmsgfromserver()		
		else:
			print "Incorrect syntax use correct keyword SEND or LIST or LOGOUT"

"""
class ClientThread(threading.Thread):

	def __init__(self,ip,port):
		threading.Thread.__init__(self)
		self.ip = ip
		print "[+] New thread started for "+ip+":"+str(port)

	def run(self):
		print "Connection from : "+ip+":"+str(port)
		clientsock.send("\nWelcome to the server\n\n")
		data = "dummydata"

"""		

#def main():
def main(argv): 
	global addr
	global g 
	global s
	g=10
	global p
	p=7
	global users_list
	global Online_USERLIST
	global inp_file, sender_private_key, recvr_private_key,encrypted_final_file,output_plaintext_file
	sender_private_key = sys.argv[2]
	recvr_private_key = sys.argv[1]
		
	"""
	scriptarg_len = len(sys.argv)
	print sys.argv[2]
	#Handling Exception for the input to be entered on Linux command line
	if(scriptarg_len != 3):
		print "Error: Either Very few or more script arguments supplied!"
		exit()
	else :
		port = int(sys.argv[2])
		if (sys.argv[2].isdigit() == False) : #performing integer check for port number
			print "Error: Port number entered is not integer value"
			exit ()
		elif (int(sys.argv[2]) > 65535): #checking for port number range
			print "Error: Entered port number is in out of range 0-65535"
		elif (sys.argv[1] != "-sp"):  #Checking for -sp syntax
			print "Error: incorrect syntax provided, Correct syntax is python ChatServer.py -sp <portno.>"
			exit()
    """
	host = '' #Default host address which is the local IP address
	#port = sys.argv[2]
	port = 9090
	#Creating UDP socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
	s.bind((host,port))
	server = (host, port) #Port 9090 obtained from command line while running scripts
	print "Server Initialized..."
	
	#Getting user details
	users_list = ['user1', 'user2', 'user3']
	global client_list
	client_list = []
	while True:
		global data, addr
		rdata = s.recvfrom(1024)
		data = rdata[0]
		addr = rdata[1]
		#print rdata
		#thread.start_new_thread(send_dataTo_client,())
		#thread.start_new_thread(receive_dataFrom_client,())
		if 'connect' in data:
			m =  re.search('(?<=connect)\w+',data)
			m1 = re.search('(?<=&&&)\w+',data)
			if 	m.group(0) in users_list:
				#checking replay attack
				#print "Executing Replay attack"
				check_replayattack(m1.group(0))
				#Checking for authentication success or failure status for users who tries to login
				status=checkUser(m.group(0))
				print "Authentication status of the user " + str(status)
				if status=="Failure":
					continue
				elif status=="Success":
					break
			else:
				send_dataTo_client("you are not a registered user")
		#receive conversation message from client
	recvmsgfromclient()
	#thread.start_new_thread(recvmsgfromclient,())
	#thread.start_new_thread(sendmsgfromserver,())
	
		#print "<- <" + "From " + str(addr[0])+":"+str(addr[1]) + ">: " + str(data)
		#data = "<- <" + "From " + str(addr[0])+":"+str(addr[1]) + ">: " + str(data)
		#if addr not in client_list:
		#	client_list.append(addr)
		#send_msgTo_client()
		
if __name__ == "__main__":
	main(sys.argv[1:])
	#main()