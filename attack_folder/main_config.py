"""zainab saad
    202472448"""
import ipaddress
# This to ensure that the user enter a valid ip, if not ask hime again
def validate_ip(get_ip):
    while True:
        ip = input(get_ip)
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            print("enter a valid ip")

# To choose a domain name that is used in dns amplification attack
def choose_from_query():
    while True:
        choose = input("choose a domain 1 or 2:\n1-dane.verisignlabs.com\n2- sigok.verteiltesysteme.net\n")
        if choose == "1":
            return 1
        elif choose == "2":
            return 2
        else:
            print("choose only 1 or 2")


def validate_ports():
    while True:
        try:
            # ask user to enter the first port number
            start_port = int(input("Enter the start port number (1-65535): "))
            # ask user to insert the second port number
            end_port = int(input("Enter the end port number (1-65535): "))
            
            # first checks if the two port number are in the correct range
            # then check if the first post less or equal to the end one to scan range of ports
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
                # if two port in the correct range , and start less or equal end 
                # return ports value
                if start_port <= end_port:
                    return start_port, end_port
                else:
                    # if not less or equal print message that should be smaller and ask user to enter agian
                    print("Start port must be less than or equal to end port")
            else:
                # if port is not in the range ask to try again
                print("Port numbers must be between 1 and 65535.")
        # if enter a value not integer ask output error and ask again for value 
        except ValueError:
            print("Invalid input. Please enter numeric values for ports.")
    

def validate_port():
    while True:
        try:
            # enter port number
            enter= input("Enter port number that range from 1-65535: ")
      
            port =int(enter)
            # first checks if the port number are in the correct range
            if 1 <= port <= 65535 :
                return port
               
            else:
                # if port is not in the range ask to try again
                print("Port numbers must be between 1 and 65535.")
        # if enter a value not integer ask output error and ask again for value 
        except ValueError:
            print("Invalid input. Please enter numeric values for ports.")
    
