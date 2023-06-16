# [chaos]()

chaos is an 'origin' IP scanner developed by RST in collaboration with ChatGPT.  It is a niche utility with an intended audience of mostly penetration testers and bug hunters.  chaos was rapidly prototyped from idea to functional proof-of-concept in less than 24 hours using our principles of DevOps with ChatGPT.

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
     (ver: 0.9.3)

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
4. `(env) pip3 install -U pip setuptools`
5. `(env) pip3 install -U -r ./requirements.txt`
6. `(env) ./chaos.py -h`

# Options
      -h, --help            show this help message and exit
      -f FQDN, --fqdn FQDN  Path to FILE with FQDNs (one per line)
      -i IP, --ip IP        IP address to send HTTP requests to (IP, comma-delimited IPs, and/or FILEs with IP/line)
      -a AGENT, --agent AGENT
                            User-Agent header value for requests
      -C, --csv             Append CSV output to OUTPUT_FILE.csv
      -D, --dns             Perform fwd/rev DNS lookups on FQDN/IP values prior to request; no impact to request action
      -j JITTER, --jitter JITTER
                            Add a 0-N second randomized delay to the sleep value
      -o OUTPUT, --output OUTPUT
                            Append text output to FILE
      -p PORTS, --ports PORTS
                            Comma-separated list of TCP ports to use (default: "80,443")
      -P, --no-prep         Do not pre-scan each IP/port with `GET /` using `Host: {IP:Port}` header to eliminate unresponsive hosts
      -r, --randomize       Randomize(ish) the order IPs/ports are tested
      -s SLEEP, --sleep SLEEP
                            Add N seconds between requests (per thread); int/dec down to 1ms
      -t TIMEOUT, --timeout TIMEOUT
                            timeout to use with requests
      -T, --test            don't send requests
      -v, --verbose         Enable verbose mode
      -x, --singlethread    Single threaded execution; for 1-2 core systems; default threads=(cores-1) if cores>2

# Examples

# Related Links
