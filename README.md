# [chaos]()

chaos is an 'origin' IP scanner developed by RST in collaboration with ChatGPT.  It is a niche utility with an intended audience of mostly penetration testers and bug hunters.  

chaos was rapidly prototyped from idea to functional proof-of-concept in less than 24 hours using our principles of DevOps with ChatGPT.

    usage: chaos.py [-h] -f FQDN -i IP [-a AGENT] [-C] [-D] [-j JITTER] [-o OUTPUT] [-p PORTS] [-P] [-r] [-s SLEEP] [-t TIMEOUT] [-T] [-v] [-x] 
             _..._
         .-'`     `'-.
       __|___________|__ 
       \               /
        `._  CHAOS _.'
           `-------`
             /   \\
            /     \\
           /       \\
          /         \\
         /           \\
        /             \\
       /               \\
      /                 \\
     /                   \\
    /_____________________\\
    CHAtgpt Origin-ip Scanner
     _______ _______ _______ _______ _______
    |\\     /|\\     /|\\     /|\\     /|\\/|
    | +---+ | +---+ | +---+ | +---+ | +---+ |
    | |H  | | |U  | | |M  | | |A  | | |N  | |
    | |U  | | |S  | | |A  | | |N  | | |C  | |
    | |M  | | |E  | | |N  | | |D  | | |O  | |
    | |A  | | |R  | | |C  | | |   | | |L  | |
    | +---+ | +---+ | +---+ | +---+ | +---+ |
    |/_____|\\_____|\\_____|\\_____|\\_____\\
    
     Origin IP Scanner developed with ChatGPT
     cha*os (n): complete disorder and confusion
     (ver: 0.9.4)

![v94_csv](https://github.com/r57-labs/chaos/assets/134399975/78235493-b623-4535-97bc-4492f5464fab)

# Features
- Threaded for performance gains
- Real-time status updates and progress bars, nice for large scans ;)
- Flexible user options for various scenarios & constraints
- Dataset reduction for improved scan times
- Easy to use CSV output

# Installation
1. Download / clone / unzip / whatever
2. `cd path/to/chaos`
3. `virtualenv env`
4. `source env/bin/activate`
5. `(env) pip3 install -U pip setuptools`
6. `(env) pip3 install -U -r ./requirements.txt`
7. `(env) ./chaos.py -h`

# Options
    -h, --help            show this help message and exit
    -f FQDN, --fqdn FQDN  Path to FQDN file (one FQDN per line)
    -i IP, --ip IP        IP address(es) for HTTP requests (Comma-separated IPs, IP networks, and/or files with IP/network per line)
    -a AGENT, --agent AGENT
                          User-Agent header value for requests
    -C, --csv             Append CSV output to OUTPUT_FILE.csv
    -D, --dns             Perform fwd/rev DNS lookups on FQDN/IP values prior to request; no impact to testing queue
    -j JITTER, --jitter JITTER
                          Add a 0-N second randomized delay to the sleep value
    -o OUTPUT, --output OUTPUT
                          Append console output to FILE
    -p PORTS, --ports PORTS
                          Comma-separated list of TCP ports to use (default: "80,443")
    -P, --no-prep         Do not pre-scan each IP/port with `GET /` using `Host: {IP:Port}` header to eliminate unresponsive hosts
    -r, --randomize       Randomize(ish) the order IPs/ports are tested
    -s SLEEP, --sleep SLEEP
                          Add N seconds before thread completes
    -t TIMEOUT, --timeout TIMEOUT
                          Wait N seconds for an unresponsive host
    -T, --test            Test-mode; don't send requests
    -v, --verbose         Enable verbose output
    -x, --singlethread    Single threaded execution; for 1-2 core systems; default threads=(cores-1) if cores>2

# Examples

## Localhost Testing

Launch python HTTP server

    % python3 -u -m http.server 8001
    Serving HTTP on :: port 8001 (http://[::]:8001/) ...

Launch ncat as HTTP on a port detected as SSL; use a loop because --keep-open can hang

    % while true; do ncat -lvp 8443 -c 'printf "HTTP/1.0 204 Plaintext OK\n\n<html></html>\n"'; done
    Ncat: Version 7.94 ( https://nmap.org/ncat )
    Ncat: Listening on [::]:8443
    Ncat: Listening on 0.0.0.0:8443

Also launch ncat as SSL on a port that will default to HTTP detection

    % while true; do ncat --ssl -lvp 8444 -c 'printf "HTTP/1.0 202 OK\n\n<html></html>\n"'; done    
    Ncat: Version 7.94 ( https://nmap.org/ncat )
    Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
    Ncat: SHA-1 fingerprint: 0208 1991 FA0D 65F0 608A 9DAB A793 78CB A6EC 27B8
    Ncat: Listening on [::]:8444
    Ncat: Listening on 0.0.0.0:8444

Prepare an FQDN file:

    % cat ../test_localhost_fqdn.txt 
    www.example.com
    localhost.example.com
    localhost.local
    localhost
    notreally.arealdomain

Prepare an IP file / list:

    % cat ../test_localhost_ips.txt 
    127.0.0.1
    127.0.0.0/29
    not_an_ip_addr
    -6.a
    =4.2
    ::1

Run the scan

- Note an IPv6 network added to IPs on the CLI
- -p to specify the ports we are listening on
- -x for single threaded run to give our ncat servers time to restart
- -s0.2 short sleep for our ncat servers to restart
- -t1 to timeout after 1 second

  
![test_local](https://github.com/r57-labs/chaos/assets/134399975/bb767838-b463-4c75-8643-d552d3e9f96c)

    % ./chaos.py -f ../test_localhost_fqdn.txt -i ../test_localhost_ips.txt,::1/126 -p 8001,8443,8444 -x -s0.2 -t1   
    2023-06-21 12:48:33 [WARN] Ignoring invalid FQDN value: localhost.local
    2023-06-21 12:48:33 [WARN] Ignoring invalid FQDN value: localhost
    2023-06-21 12:48:33 [WARN] Ignoring invalid FQDN value: notreally.arealdomain
    2023-06-21 12:48:33 [WARN] Error: invalid IP address or CIDR block =4.2
    2023-06-21 12:48:33 [WARN] Error: invalid IP address or CIDR block -6.a
    2023-06-21 12:48:33 [WARN] Error: invalid IP address or CIDR block not_an_ip_addr
    2023-06-21 12:48:33 [INFO] * ---- <META> ---- *
    2023-06-21 12:48:33 [INFO] * Version: 0.9.4
    2023-06-21 12:48:33 [INFO] * FQDN file: ../test_localhost_fqdn.txt
    2023-06-21 12:48:33 [INFO] * FQDNs loaded: ['www.example.com', 'localhost.example.com']
    2023-06-21 12:48:33 [INFO] * IP input value(s): ../test_localhost_ips.txt,::1/126
    2023-06-21 12:48:33 [INFO] * Addresses parsed from IP inputs: 12
    2023-06-21 12:48:33 [INFO] * Port(s): 8001,8443,8444
    2023-06-21 12:48:33 [INFO] * Thread(s): 1
    2023-06-21 12:48:33 [INFO] * Sleep value: 0.2
    2023-06-21 12:48:33 [INFO] * Timeout: 1.0
    2023-06-21 12:48:33 [INFO] * User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 ch4*0s/0.9.4
    2023-06-21 12:48:33 [INFO] * ---- </META> ---- *
    2023-06-21 12:48:33 [INFO] 36 unique address/port addresses for testing
    Prep Tests: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 36/36 [00:29<00:00,  1.20it/s]
    2023-06-21 12:49:03 [INFO] 9 IP/ports verified, reducing test dataset from 72 entries
    2023-06-21 12:49:03 [INFO] 18 pending tests remain after pre-testing
    2023-06-21 12:49:03 [INFO] Queuing 18 threads
      ++RCVD++ (200 OK) www.example.com @ :::8001                                                                                                                                                    
      ++RCVD++ (204 Plaintext OK) www.example.com @ :::8443                                                                                                                                          
      ++RCVD++ (202 OK) www.example.com @ :::8444                                                                                                                                                    
      ++RCVD++ (200 OK) www.example.com @ ::1:8001                                                                                                                                                   
      ++RCVD++ (204 Plaintext OK) www.example.com @ ::1:8443                                                                                                                                         
      ++RCVD++ (202 OK) www.example.com @ ::1:8444                                                                                                                                                   
      ++RCVD++ (200 OK) www.example.com @ 127.0.0.1:8001                                                                                                                                             
      ++RCVD++ (204 Plaintext OK) www.example.com @ 127.0.0.1:8443                                                                                                                                   
      ++RCVD++ (202 OK) www.example.com @ 127.0.0.1:8444                                                                                                                                             
      ++RCVD++ (200 OK) localhost.example.com @ :::8001                                                                                                                                              
      ++RCVD++ (204 Plaintext OK) localhost.example.com @ :::8443                                                                                                                                    
      ++RCVD++ (202 OK) localhost.example.com @ :::8444                                                                                                                                              
      ++RCVD++ (200 OK) localhost.example.com @ ::1:8001                                                                                                                                             
      ++RCVD++ (204 Plaintext OK) localhost.example.com @ ::1:8443                                                                                                                                   
      ++RCVD++ (202 OK) localhost.example.com @ ::1:8444                                                                                                                                             
      ++RCVD++ (200 OK) localhost.example.com @ 127.0.0.1:8001                                                                                                                                       
      ++RCVD++ (204 Plaintext OK) localhost.example.com @ 127.0.0.1:8443                                                                                                                             
      ++RCVD++ (202 OK) localhost.example.com @ 127.0.0.1:8444                                                                                                                                       
    Origin Scan: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 18/18 [00:06<00:00,  2.76it/s]
    2023-06-21 12:49:09 [RSLT] Results from 5 FQDNs:
      ::1
        ::1:8444 => (202 / OK)
        ::1:8443 => (204 / Plaintext OK)
        ::1:8001 => (200 / OK)
    
      127.0.0.1
        127.0.0.1:8001 => (200 / OK)
        127.0.0.1:8443 => (204 / Plaintext OK)
        127.0.0.1:8444 => (202 / OK)
    
      ::
        :::8001 => (200 / OK)
        :::8443 => (204 / Plaintext OK)
        :::8444 => (202 / OK)
    
      www.example.com
        :::8001 => (200 / OK)
        :::8443 => (204 / Plaintext OK)
        :::8444 => (202 / OK)
        ::1:8001 => (200 / OK)
        ::1:8443 => (204 / Plaintext OK)
        ::1:8444 => (202 / OK)
        127.0.0.1:8001 => (200 / OK)
        127.0.0.1:8443 => (204 / Plaintext OK)
        127.0.0.1:8444 => (202 / OK)
    
      localhost.example.com
        :::8001 => (200 / OK)
        :::8443 => (204 / Plaintext OK)
        :::8444 => (202 / OK)
        ::1:8001 => (200 / OK)
        ::1:8443 => (204 / Plaintext OK)
        ::1:8444 => (202 / OK)
        127.0.0.1:8001 => (200 / OK)
        127.0.0.1:8443 => (204 / Plaintext OK)
        127.0.0.1:8444 => (202 / OK)
    
    
    rst@r57 chaos % 

## Test & Verbose localhost

`-T` runs in test mode (do everything except send requests)

`-v` verbose option provides additional output

![test_local_verbose](https://github.com/r57-labs/chaos/assets/134399975/738b29f0-1b5e-4923-8303-34c7137724aa)


# Related Links

