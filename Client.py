#from threading import Thread
import socket ,sys , random
import time, re
import thread
import hashlib
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



def encodetext_Toserver (data_msg):
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

def decodetext_Fromserver (text):
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
	
#Input message from user
def input_msg() :
	print "Enter message to send:"
	sys.stdout.write('=>')
	sys.stdout.flush()

#For receiving data like user_timestamp and password to server for authentication purpose	
def receive_dataFrom_server():
	global data
	rdata = s.recvfrom(4096)
	data = rdata[0]
	addr = rdata[1]

#For receiving conversation message         
def receive_msgFrom_server():
	while(1): 
		rdata = s.recvfrom(1024)
		#print "message before decoding " + str(rdata)
		#performing decoding operation after receiving from server
		message = decodetext_Fromserver(rdata[0])
		#print "message after decoding " + str(message)
		addr = rdata[1]
		reply = message
		#print addr
		#print reply
		sys.stdout.write(reply)
		input_msg()

#For send message to server
def send_msgTo_server():
	global server, message, s
	print "Sending actual conversation message to server, Syntax is <SEND> <msg> or LIST or LOGOUT"
	while True:
		message = sys.stdin.readline()
		if "LOGOUT" in message:
			print "User Client is Logged off!!"
			sys.exit()
			s.close()
		#print "message before encoding " + str(message)
		#Performing encoding operation
		message = encodetext_Toserver(message)
		s.sendto(message, server)
		input_msg()
		
#For send data like user_timestamp and password to server for authentication purpose	
def send_dataTo_server(reply):
	#print "executing sendDataToServer"
	global server
	#print server
	#print reply
	s.sendto(reply,server)

#For checking replay attack	
def check_replayattack(timestamp):
	current_timestamp=time.time()
	if (int(timestamp)+5) > current_timestamp:
		#print "Client Side: Its Secure, No replayattack is ON"
		pass
	else :
		print "Client Side: Alert: Replayattack is performed Fix it"

#		
def perform_login():
	#setting value of g and p for diffie-hellman algorithm
	g=10
	p=7
	
	user = raw_input("Enter your username to start chatting : ")
	current_timestamp=time.time()
	#sending username and timestamp to the server
	user_timestamp = 'connect'+str(user)+'&&&'+str(current_timestamp)
	#print "Client side user_timestamp"
	#print user_timestamp
	send_dataTo_server(user_timestamp)
	receive_dataFrom_server()
	if '&&&' not in data:
		print data
		return "invalid"
	# Removing salt portion from the message	
	m =  re.split(r'&&&',data)
	m1 = re.search('(?<=&&&)\w+',data)
	#checking replay attack 
	check_replayattack(m1.group(0))
	password = raw_input("Enter your password to continue : ")
	current_timestamp=time.time()
	#creating DiffiHellman key for Server FOR PREVENTING DOS ATTACK
	DiffiHellman_key=generateDiffieHellamanKeys()
	#DiffiHellman_key=g^2 % p
	#sending user + salt + password + salt + timestamp + DiffiHellman_key to the server
	#password_data = str(user) + '&&&' + password + m[0] + '&&&' + str(current_timestamp) + '&&&' + str(DiffiHellman_key)
	password_data = str(user) + '&&&' + password + '&&&' + str(current_timestamp) + '&&&' + str(DiffiHellman_key)
	#print "client side password data"
	#print password_data
	send_dataTo_server(password_data)
	#check for decision status from Server
	receive_dataFrom_server()
	#print data[0]
	if "invalid" in data[0]:
		return "invalid"
	#Receiving DiffiHellman Key from server
	receive_dataFrom_server()
	m =  re.split(r'&&&',data)
	#checking replay attack 
	check_replayattack(int(float(m[1])))
	symkey=(int(m[0]))^2
	print "---------------------------------------"
	#print symkey
	return "success"
"""
def generateClientPublicKey():
    private_key = generateClientPrivateKey()
    public_key = private_key.public_key()
    
def generateClientPrivateKey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
        )
    return private_key
"""
def generateDiffieHellamanKeys():
	d1 = pyDH.DiffieHellman(16) # Uses 4096 bit key
	d1_pubkey = d1.gen_public_key() # d1_pubkey is g^c mod p
	return d1_pubkey
	
#def main(): 
def main(argv): 
	global s, server
	global inp_file, sender_private_key, recvr_private_key,encrypted_final_file,output_plaintext_file
	sender_private_key = sys.argv[2]
	recvr_private_key = sys.argv[1]
	"""
	#Handling Exception for the input to be entered on Linux command line
	scriptarg_len = len(sys.argv)
	if(scriptarg_len != 5):
		print "Error: Either Very few or more script arguments supplied!"
		exit()
	else :
		server_ip = sys.argv[2]
		server_port = int(sys.argv[4])
		if (sys.argv[4].isdigit() == False) : #performing integer check for port number
			print "Error: Port number entered is not integer value"
			exit ()
		elif (int(sys.argv[4]) > 65535): #checking for port number range
			print "Error: Entered port number is in out of range 0-65535"
		elif (sys.argv[1] != "-sip") and (sys.argv[3] != "-sp"):  #Checking for -sp syntax
			print "Error: incorrect syntax provided, Correct syntax is python ChatClient.py -sip <server_ip> -sp <portno.>"
			exit()

    """
	
	#Creating a UDP socket
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	global message
	server_ip = "localhost"
	server_port = 9090
	#server = (server_ip, server_port)
	host = "127.0.0.1"
	#port = random.randrange(8000, 8003)
	port = 9090
	server = (host, port)
	"""
	try:
		s.bind((host, port))
	except:
		print "Error in binding port"
		exit()
	"""	
	#Calling login protocol function
	while (1):
		login_status = perform_login()
		print "Currently Logged in User Status is  " + str(login_status)
		#print login_status
		if login_status=='invalid':
			continue
		else:
			break
	#Create threads for multiple clients
	thread.start_new_thread(send_msgTo_server,())
	thread.start_new_thread(receive_msgFrom_server,())
	"""
	listen_thread = Thread(target = receive_msgFrom_server)
	send_thread = Thread(target = send_msgTo_server)
	listen_thread.setDaemon(True)
	send_thread.setDaemon(True)
	listen_thread.start()
	send_thread.start()
	"""
	while True:
		pass

if __name__ == "__main__":
	main(sys.argv[1:])
	#main()