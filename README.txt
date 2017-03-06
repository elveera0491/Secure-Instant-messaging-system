There is a client server implementation of the login protocol and cryptographic protocols implemented to a certain extent.It generates public and private keys
implicitly, cookie to prevent DOS attack, Diffie Hellman for secret key.
That was our initial idea to develop the code. Later, we started working on the basic functionality and that's present in the the Client.py and Server.py files.

High Level Approach:
1. A chat application was implemented wherein two clients can communicate with each other.
2. A server is present to authenticate users and knows all online users.
3. LIST command is used to show the list of online users.
4. SEND command is used to send messages.
5. LOGOUT command is used for the client to logout of the chat session.
6. Asymmetric key encryption is used to encrypt and decrypt messages exchanged between server and client.
7. The same key is used to sign the message.


How to run the script:
1. Save the file in a directory.
2. To run Server, use the command: python Server.py rpkey spkey
3. To run Client, use the command: python Client.py rpkey spkey
4. Make sure that the path entered for execution of both the programs is the path where the Server.py, Client.py, rpkey, spkey are stored.
