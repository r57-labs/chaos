#!/usr/bin/env python3
#
# CHAtgpt Origin-ip Scanner
#
import argparse
import csv		# output file
import datetime		# logging
import os		# file validation, cpu count
import ipaddress 	# for CIDR support
import logging
import random		# for -r flag to randomize IPs
import re
import requests		# for modified web requests
import socket 		# ip addr valition, and dns lookups
import time		# rate limiting
import warnings		# filter/ignore unverified https

from concurrent.futures import ThreadPoolExecutor, as_completed # threads!
from tld import get_tld						# validate FQDNs without regex
from tqdm import tqdm                                           # progress bar?!

__version__ = '0.9.4'

ascii_art = r'''
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
'''

# Thread Metadata
nouns = ['acorn', 'air', 'area', 'bag', 'ball', 'band', 'base', 'bird', 'block', 'boat', 'book', 'boss', 'bottle', 'box', 'brake', 'branch', 'bread',
         'breath', 'brick', 'bridge', 'brush', 'bucket', 'building', 'business', 'button', 'car', 'card', 'cat', 'chair', 'chalk', 'chance',
         'change', 'chicken', 'circle', 'city', 'clock', 'cloth', 'cloud', 'coat', 'collar', 'color', 'comfort', 'committee', 'company',
         'condition', 'connection', 'control', 'cook', 'copper', 'copy', 'cord', 'cork', 'country', 'cover', 'cow', 'credit', 'cup', 'current',
         'curtain', 'curve', 'cushion', 'damage', 'danger', 'day', 'debt', 'decision', 'degree', 'design', 'desk',
         'detail', 'digest', 'direction', 'discovery', 'discussion', 'distance',
         'division', 'dog', 'door', 'doubt', 'drink', 'driving', 'drop', 'ear', 'earth', 'edge', 'education', 'effect', 'egg', 'end', 'error', 'event',
         'example', 'exchange', 'existence', 'expansion', 'experience', 'expert', 'eye', 'face', 'fact']
adjectives = ['able', 'acid', 'angry', 'automatic', 'awake', 'bad', 'beautiful', 'bent', 'bitter', 'black', 'blue', 'boiling', 'bright', 'broken', 'brown',
              'bumpy', 'burning', 'busy', 'calm', 'careful', 'cheap', 'chief', 'clean', 'clear', 'cold', 'common', 'complete', 'complex', 'conscious',
              'cooked', 'cool', 'crazy', 'creepy', 'crooked', 'crowded', 'cruel', 'curly', 'curved', 'cut', 'damp', 'dangerous', 'dark', 'deep',
              'delicious', 'different', 'dry', 'dull', 'dusty', 'early', 'easy', 'elastic', 'electric', 'empty', 'faint', 'fair', 'false', 'fat',
              'feeble', 'few', 'fierce', 'fine', 'flat', 'fluffy', 'foolish', 'foreign', 'fragile', 'free', 'frozen', 'full',
              'gentle', 'gifted', 'glad', 'glass', 'glorious', 'good', 'gray', 'great', 'green', 'grumpy', 'handsome', 'happy', 'harsh', 'healthy',
              'heavy', 'high', 'hollow', 'hot', 'huge', 'hungry', 'ill', 'important', 'impossible', 'inexpensive', 'itchy', 'jealous',
              'jittery', 'jolly', 'juicy', 'kind', 'large', 'late']


# obligatory kludge
logger = None

############################################################################################
## HELPERS

class LogStyle:
    """
    Defines the output format
    """
    DEBUG =           '[----]'
    INFO =            '[INFO]'
    GOOD =    '\033[92m[++++]\033[0m'
    RSLT =    '\033[92m[RSLT]\033[0m'
    WARN =    '\033[93m[WARN]\033[0m'
    ERROR =   '\033[91m[!!!!]\033[0m'
    TIMESTAMP = '%Y-%m-%d %H:%M:%S'

class TqdmLoggingHandler(logging.Handler):
    """
    Interface to logging.handler for intercepting log output in progress bars
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

class Logger:
    """
    A class for managing output to console and file
    """
    def __init__(self, level=logging.INFO, timestamp=True, output_file=None, verbose=False):
        self.timestamp = timestamp
        self.verbose = verbose
        self.logger = logging.getLogger()
        self.logger.setLevel(level)
        self.console_handle = TqdmLoggingHandler()
        self.logger.addHandler(self.console_handle)
        if not output_file is None:
            if os.path.exists(output_file.name) and os.stat(output_file.name).st_size > 0:
                msg = LogStyle.INFO + ' ' + f"Appending to existing file: {output_file.name}"
                msg = datetime.datetime.now().strftime(LogStyle.TIMESTAMP) + ' ' + msg if self.timestamp else None
                self.logger.info(msg)
            file_handler = logging.FileHandler(output_file.name)
            file_handler.setLevel(level)
            self.logger.addHandler(file_handler)

    def log(self, message, level='INFO', indent=0):
        """
        A method for managing output to console and file
        """
        message = ' ' * indent + message

        # only print debug if we're verbose
        if level == 'DEBUG' and not self.verbose:
            return

        # apply the log styling, using info if we don't know what style to use
        if level not in [attr for attr in dir(LogStyle) if attr[0].isupper()]:
            message = LogStyle.INFO + ' ' + message
        else:
            message = f"{getattr(LogStyle, level)}" + ' ' + message

        if self.timestamp:
            message = datetime.datetime.now().strftime(LogStyle.TIMESTAMP) + ' ' + message

        self.logger.info(message)
        self.console_handle.flush()
        
class TestTarget:
    """
    Object to handle data for testing targets
    """
    def __init__(self, ip, port, fqdn):
        self.ip = ip
        self.port = port
        self.fqdn = fqdn

    def __str__(self):
        return f"IP: {self.ip}, Port: {self.port}, FQDN: {self.fqdn}"

class PrepResult:
    """
    Object to handle result data from the prep run
    """
    def __init__(self, ip, port, response):
        self.ip = ip
        self.port = port
        self.response = response
    def __str__(self):
        return f"IP: {self.ip}, Port: {self.port}, Status: {self.response.status_code}, Reason: {self.response.reason}"

class TestResult:
    """
    Object to handle result data from the test
    """
    def __init__(self, fqdn, ip, port, response):
        self.fqdn = fqdn
        self.ip = ip
        self.port = port
        self.response = response

def validate_user_agent_param(value):
    """
    Param value tested against whitelist of common UA characters
    """
    ua_pattern = f"^[a-zA-Z0-9\-\._\s;\/\(\):\*,\+]+$"
    try:
        if not re.match(ua_pattern, value):
            raise argparse.ArgumentTypeError(f"User-Agent does not match regexp /^[a-zA-Z0-9\-\._\s;\/\(\):\*,\+]+$/")
    except Exception as e:
            logger.log(f'Unable to parse user-agent value: {value}', level='ERROR')
            logger.log(f'{e}', level='DEBUG')
            exit(1)
    
def validate_time_param(value):
    """
    Param value should be an int or float >= 1ms
    """
    try:
        time_val = float(value)
        if time_val < 0.001:
            raise argparse.ArgumentTypeError("Sleep/Jitter/Timeout values should be at least 1ms")
        return time_val
    except ValueError:
        raise argparse.ArgumentTypeError("Sleep/Jitter/Timeout values should be a valid integer or float")

def parse_ip_param(param):
    """
    Handle IP param value(s) as IP, comma-delimited IPs, and/or FILEs with IP/line
    """
    tmp_ips = []
    valid_ips = []
    ret_ips = []

    # split the parameter 
    param_data = param.split(',') if ',' in param else [param]
    logger.log(f"IP parameter data := {param_data}", 'DEBUG')

    # check each value that could be a file or an IP
    for param_val in param_data:
        if os.path.isfile(param_val):
            logger.log(f"IP param value is a file, reading {param_val}", 'DEBUG')
            try:
                with open(param_val, 'r') as f:
                    tmp_ips.extend([line.strip() for line in f.readlines()])
            except Exception as e:
                logger.log(f'Unable to read/parse: {param_val}', level='WARN')
                logger.log(f'{e}', level='DEBUG')
                continue
        else:
            logger.log(f"IP param value is not a file, extending {[param_val.strip()]}", 'DEBUG')
            tmp_ips.extend([param_val.strip()])
    
    logger.log(f"Found {len(tmp_ips)} temporary IPs", 'DEBUG')
    tmp_ips = list(set(tmp_ips))
    logger.log(f"De-dupe complete; have {len(tmp_ips)} temporary IPs", 'DEBUG')
    logger.log(f"Starting network checks; tmp_ips := {tmp_ips}", 'DEBUG')
    # convert networks to ips
    for ip in tmp_ips:
        logger.log(f"Testing value: {ip}", 'DEBUG')
        try:
            # test for CIDR
            network = ipaddress.ip_network(ip, strict=False)
            logger.log(f"Addr value {ip} parsed as ipaddress.ip_network(); extending records", 'DEBUG')  
            # also capture the network and broadcast addresses when pulling IPs from network
            valid_ips.append(str(network.network_address)) if "/" in ip else None
            valid_ips.extend([str(ip) for ip in network.hosts()])
            valid_ips.append(str(network.broadcast_address)) if "/" in ip else None
        except ValueError as ve:
            # on error assume it's ipv4/ipv6
            logger.log(f"IPv4/IPv6 testing addr value {ip}", 'DEBUG')
            try:
                ip = ipaddress.ip_address(ip) 
                valid_ips.append(str(ip))
            except ValueError as e:
                logger.log(f'Error: invalid IP address or CIDR block {ip}', 'WARN')
                continue
            except Exception as e:
                logger.log(f'Unable to parse IP value: {ip}', level='WARN')
                logger.log(f'{e}', level='DEBUG')
                continue
        except Exception as e:
            logger.log(f'Unable to parse IP value as ip_network: {ip}', level='WARN')
            logger.log(f'{e}', level='DEBUG')
            continue

    logger.log(f"Network checks complete; have {len(valid_ips)} IPs", 'DEBUG')
    valid_ips = list(set(valid_ips))
    logger.log(f"De-dupe complete; have {len(valid_ips)} IPs", 'DEBUG')

    # verify the ip values are legit(-ish) by using socket to try to convert string IP addrs
    for ip in valid_ips:
        try:
            socket.inet_pton(socket.AF_INET, ip)
            ret_ips.append(ip)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                ret_ips.append(ip)
            except OSError:
                logger.log(f'Error: invalid IP address or CIDR block {ip}', 'WARN')
            except Exception as e:
                logger.log(f'Unable to call socket.inet_pton() using AF_INET6 on IP value: {ip}', level='WARN')
                logger.log(f'{e}', level='DEBUG')
                continue
        except Exception as e:
            logger.log(f'Unable to call socket.inet_pton() using AF_INET on IP value: {ip}', level='WARN')
            logger.log(f'{e}', level='DEBUG')
            continue

    logger.log(f"Validation complete; have {len(ret_ips)} IPs", 'DEBUG')
    ret_ips = list(set(ret_ips))
    logger.log(f"De-dupe complete; have {len(ret_ips)} IPs", 'DEBUG')
    return ret_ips

def get_response_content_summary(response):
    """
    Do the things to print a response summary in the CSV output
    """
    cont_enc = "utf-8" # default encoding
    ctnt = ""
    resp_ctnt = ""

    # check encoding if it's there (finding the key due to not knowing the case of the characters)
    content_encoding_key = next((key for key in response.headers if key.lower() == 'content-encoding'), None)
    if content_encoding_key is not None:
        cont_enc = response.headers[content_encoding_key].lower().strip()

    # seems like requests handles gzip automagically when decoding
    if cont_enc.lower() == 'gzip':
        try:
            ctnt = response.content.decode('utf-8')
        except Exception as e:
            logger.log(f"Error using requests to decode '{cont_enc}' content-type for response {response.content}", 'ERROR')
            logger.log(f"{e}", 'DEBUG')
    # so if we ever get here with a value besides 'utf-8', maybe expect errors?
    else:
        try:
            ctnt = response.content.decode(cont_enc)
        except Exception as e:
            logger.log(f"Error using requests to decode '{cont_enc}' content-type for response {response.content}", 'ERROR')
            logger.log(f"{e}", 'DEBUG')

    if ctnt != "":
        for i, line in enumerate(ctnt.split('\n')):
            # TBD: make this a variable or option
            if i >= 20:
                resp_ctnt = resp_ctnt + "...\n"
                break
            # TBD: also variable/opt
            if len(line) > 240:
                resp_ctnt = resp_ctnt + line[:240] + "...\n"
            else:
                resp_ctnt = resp_ctnt + line + "\n"
    if resp_ctnt != "":
        # replace newlines with a delimiter
        #resp_ctnt = re.sub('\n+', '~~#~~', str(resp_ctnt))
        resp_ctnt = re.sub('\n+', '\n', str(resp_ctnt))
        # remove whitespace lines from delimited data
        #resp_ctnt = re.sub('^~~#~~\s+', '', resp_ctnt)
        resp_ctnt = re.sub('^\s+', '', resp_ctnt)
        # replace multi whitespace with single space
        resp_ctnt = re.sub('\s+', ' ', resp_ctnt)
        # remove double and single quotes
        resp_ctnt = re.sub('"', '', resp_ctnt)
        resp_ctnt = re.sub("'", '', resp_ctnt)
    return resp_ctnt

def looks_ipv6(addr):
    """
    Quick check; assumes a prior validated IPv[4|6] addr will have no dot and will have a colon if it's IPv6
    """
    return '.' not in addr and ':' in addr

def prep_thread_worker(ip, port, agent, test, timeout, verbose, thread_id, sleep_val):
    """
    Support threading for prep task to check if IP/PORT is responsive to 'GET /' using 'Host: {ip}:{port}'
    """
    result = None
    proto = "http"
    # TBD: implement a better SSL/TLS protocol check
    #      it may be getting 'better', but it's a kludge/cluster
    if port == '443' or re.match('.*443.*', port):
        proto = 'https'
    if looks_ipv6(ip):
        url = f"{proto}://[{ip}]:{port}/"
    else:
        url = f"{proto}://{ip}:{port}/"
    headers = {'Host': f"{ip}:{port}"}
    if agent:
        headers.update({'User-Agent': agent})
    if test:
        return
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=timeout)
        # any HTTP response is considered a result
        if response.status_code // 100 in [1, 2, 3, 4, 5]:
            result = PrepResult(ip, port, response)
    except requests.exceptions.RequestException as e:
        err_msg = re.sub(r"[\r\n]+", "", str(e))
        if "connection reset by peer" in err_msg.lower() and proto == "http":
            if verbose:
                tqdm.write(f"  [prep-check] [{thread_id}] Trying HTTPS protocol after reset from HTTP connection")
            if sleep_val > 0:
                time.sleep(sleep_val)
            try:
                response = requests.get(f"https://{url.split('http://')[1]}", headers=headers, verify=False, allow_redirects=False, timeout=timeout)
                if response.status_code // 100 in [1, 2, 3, 4, 5]:
                    result = PrepResult(ip, port, response)
            except requests.exceptions.RequestException as e:
                # ignore hosts that do not respond
                None
        elif "caused by sslerror" in err_msg.lower() and proto == "https":
            if verbose:
                tqdm.write(f"  [prep-check] [{thread_id}] Trying HTTP protocol after SSLError from HTTPS connection")
            if sleep_val > 0:
                time.sleep(sleep_val)
            try:
                response = requests.get(f"http://{url.split('https://')[1]}", headers=headers, verify=False, allow_redirects=False, timeout=timeout)
                if response.status_code // 100 in [1, 2, 3, 4, 5]:
                    result = PrepResult(ip, port, response)
            except requests.exceptions.RequestException as e:
                # ignore hosts that do not respond
                None
        elif "retries exceeded" in err_msg.lower() and any(err_str in err_msg for err_str in ["ConnectTimeoutError", "NewConnectionError"]):
            # ignore hosts that do not respond
            None
        else:
            tqdm.write(f"  [prep-check] [{thread_id}] RequestException: {e}")
    except Exception as e:
        tqdm.write(f"  [prep-check] [{thread_id}] ERROR: {e}")
    if sleep_val > 0:
        time.sleep(sleep_val) # sleep between requests
    return result

def notify_rslt(fqdn, ip, port, response):
    """
    Output result info to screen using tqdm while thread_worker is running
    """
    if (response.status_code // 100 == 3):
        # trim the 3xx location for display
        resp_loc = response.headers['Location']
        if len(resp_loc) > 100:
            resp_loc = f"{resp_loc[0:99]}..."
        tqdm.write(f"  \033[92m++RCVD++\033[0m ({response.status_code} {response.reason}) {fqdn} @ {ip}:{port} ==> {resp_loc}")
    else:
        tqdm.write(f"  \033[92m++RCVD++\033[0m ({response.status_code} {response.reason}) {fqdn} @ {ip}:{port}")

def thread_worker(ip, port, fqdn, agent, test, timeout, verbose, thread_id, sleep_val):
    """
    Support threading for testing IP:PORT using FQDN in HTTP Host header
    """
    result = None
    proto = "http"
    # TBD: implement a better SSL/TLS protocol check
    if port == '443' or re.match('.*443.*', port):
        proto = 'https'
    if looks_ipv6(ip):
        url = f"{proto}://[{ip}]:{port}/"
    else:
        url = f"{proto}://{ip}:{port}/"
    headers = {'Host': f"{fqdn}"}
    if agent:
        headers.update({'User-Agent': agent})
    if test:
        return
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=timeout)
        if response.status_code // 100 in [1, 2, 3, 4, 5]:
            notify_rslt(fqdn, ip, port, response)
            result = TestResult(fqdn, ip, port, response)
    except requests.exceptions.RequestException as e:
        err_msg = re.sub(r"[\r\n]+", "", str(e))
        # if we get this error with HTTP, let's try HTTPS
        if "connection reset by peer" in err_msg.lower() and proto == "http":
            if verbose:
                tqdm.write(f"  [{thread_id}] Trying HTTPS protocol after reset from HTTP connection")
            if sleep_val > 0:
                time.sleep(sleep_val)
            try:
                response = requests.get(f"https://{url.split('http://')[1]}", headers=headers, verify=False, allow_redirects=False, timeout=timeout)
                if response.status_code // 100 in [1, 2, 3, 4, 5]:
                    notify_rslt(fqdn, ip, port, response)
                    result = TestResult(fqdn, ip, port, response)
            except requests.exceptions.RequestException as e:
                # ignore hosts that do not respond
                None
        elif "caused by sslerror" in err_msg.lower() and proto == "https":
            if verbose:
                tqdm.write(f"  [{thread_id}] Trying HTTP protocol after SSLError from HTTPS connection")
            if sleep_val > 0:
                time.sleep(sleep_val)
            try:
                response = requests.get(f"http://{url.split('https://')[1]}", headers=headers, verify=False, allow_redirects=False, timeout=timeout)
                if response.status_code // 100 in [1, 2, 3, 4, 5]:
                    notify_rslt(fqdn, ip, port, response)
                    result = TestResult(fqdn, ip, port, response)
            except requests.exceptions.RequestException as e:
                # ignore hosts that do not respond
                None
        elif "retries exceeded" in err_msg.lower() and any(err_str in err_msg for err_str in ["ConnectTimeoutError", "NewConnectionError"]):
            # ignore hosts that do not respond
            None
        else:
            tqdm.write(f"  [{thread_id}] RequestException: {e}")
    except Exception as e:
        tqdm.write(f"  [{thread_id}] ERROR: {e}")
    if sleep_val > 0:
        time.sleep(sleep_val) # sleep between requests
    return result



############################################################################################
## MAIN
def main():

    ###########################
    # Parse command line arguments
    parser = argparse.ArgumentParser(description=f'''{ascii_art}\n\n Origin IP Scanner developed with ChatGPT\n cha*os (n): complete disorder and confusion\n (ver: {__version__})''', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser._optionals.max_help_position = 70
    parser.add_argument('-f', '--fqdn', type=argparse.FileType('r'), help='Path to FQDN file (one FQDN per line)', required=True)
    parser.add_argument('-i', '--ip', type=str, help='IP address(es) for HTTP requests (Comma-separated IPs, IP networks, and/or files with IP/network per line)', required=True)
    parser.add_argument('-a', '--agent', type=str, help='User-Agent header value for requests', default=f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 ch4*0s/{__version__}", required=False)
    parser.add_argument('-C', '--csv', action='store_true', help='Append CSV output to OUTPUT_FILE.csv')
    parser.add_argument('-D', '--dns', action='store_true', help='Perform fwd/rev DNS lookups on FQDN/IP values prior to request; no impact to testing queue')
    parser.add_argument('-j', '--jitter', type=validate_time_param, help='Add a 0-N second randomized delay to the sleep value', required=False)
    parser.add_argument('-o', '--output', type=argparse.FileType('a'), help='Append console output to FILE')
    parser.add_argument('-p', '--ports', type=str, default='80,443', help='Comma-separated list of TCP ports to use (default: "80,443")')
    parser.add_argument('-P', '--no-prep', action='store_true', help='Do not pre-scan each IP/port with `GET /` using `Host: {IP:Port}` header to eliminate unresponsive hosts')
    parser.add_argument('-r', '--randomize', action='store_true', help="Randomize(ish) the order IPs/ports are tested")
    parser.add_argument('-s', '--sleep', type=validate_time_param, help='Add N seconds before thread completes', required=False)
    parser.add_argument('-t', '--timeout', type=validate_time_param, help='Wait N seconds for an unresponsive host', default=3)
    parser.add_argument('-T', '--test', action='store_true', help="Test-mode; don't send requests")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-x', '--singlethread', action='store_true', help='Single threaded execution; for 1-2 core systems; default threads=(cores-1) if cores>2')
    args = parser.parse_args()

    ###########################
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO 
    logging.getLogger("urllib3").setLevel(logging.WARNING)		# supress verbose 'requests' output when running w/ -v (bc we are using streamhandler)
    global logger 							# kludge so we don't have to pass logger to helper functions
    logger = Logger(level, True, args.output, args.verbose)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request') 	# ignore SSL/TLS errors

    ###########################
    # Validate CSV
    csv_file = None
    if args.csv and not args.output:
        parser.error(f"CSV output requires output file option")
        exit(1)
    elif args.csv and args.output:
        csv_file=f"{str(args.output.name)}.csv"

    # TBD: verify if we want to keep this bc of something in v1 or what
    if not requests.__version__.startswith('2.'):
        raise ImportError('This script requires requests 2.x')

    ###########################
    # Validate FQDN
    if not os.path.exists(args.fqdn.name):
        parser.error('Error: FQDNs file does not exist')
        exit(1)
    if not os.access(args.fqdn.name, os.R_OK):
        parser.error('Error: FQDNs file is not readable')
        exit(1)
    valid_fqdns = []
    try:
        with open(args.fqdn.name, 'r') as f:
            for line in f:
                tmp_fqdn = line.strip()
                try:
                    # non-regex method to validate potential FQDNs
                    tld_rslt = get_tld(tmp_fqdn, as_object=True, fix_protocol=True)
                    if tld_rslt.parsed_url.netloc == tmp_fqdn:
                        valid_fqdns.append(tmp_fqdn)
                    else:
                        logger.log(f"Ignoring FQDN value ({tmp_fqdn}) that does not match tld netloc ({tld_rslt.netloc})", level='WARN')
                except (ValueError, AttributeError):
                    logger.log(f"Ignoring invalid FQDN value: {tmp_fqdn}", level='WARN')
                except Exception as e:
                    logger.log(f'Error with FQDN value: {tmp_fqdn}', level='WARN')
                    logger.log(f'{e}', level='DEBUG')
    except Exception as e:
        logger.log(f'Unable to read/parse: {args.fqdn.name}', level='ERROR')
        logger.log(f'{e}', level='DEBUG')
        parser.error(f"Unexpected error reading {args.fqdn.name}")
        exit(1)
    if len(valid_fqdns) < 1:
        parser.error(f"No valid FQDNs found in {args.fqdn.name}")
        exit(1)

    ###########################
    # Validate IP(s)
    ips = parse_ip_param(args.ip)
    if len(ips) == 0:
        parser.error(f"No valid IP values found in IP parameter: {args.ip}")
    else:
        logger.log(f"{len(ips)} IP addresses parsed from '{args.ip}' := {ips}", 'DEBUG')

    ###########################
    # Validate TCP ports
    ports = args.ports.split(',')
    for port in ports:
        try:
            port_num = int(port)
            if port_num < 0 or port_num > 65535:
                raise ValueError
        except ValueError:
            parser.error(f'Error: invalid TCP port value: {port}')

    ###########################
    # Prep threads
    socket.setdefaulttimeout(float(args.timeout))
    if args.singlethread:
        max_threads = 1
    else:
        if os.cpu_count() > 2:
            max_threads = (os.cpu_count() - 1)
        else:
            max_threads = os.cpu_count()

    sleep_val = args.sleep if args.sleep else 0

    ###########################
    # Status Info
    logger.log(f'* ---- <META> ---- *')
    logger.log(f'* Version: {__version__}')
    logger.log(f'* FQDN file: {args.fqdn.name}')
    logger.log(f'* FQDNs loaded: {valid_fqdns}')
    logger.log(f'* IP input value(s): {args.ip}')
    logger.log(f'* Addresses parsed from IP inputs: {len(ips)}')
    logger.log(f'* Port(s): {args.ports}')
    logger.log(f'* Thread(s): {max_threads}')
    logger.log(f'* Sleep value: {args.sleep}') if args.sleep else None
    logger.log(f'* Jitter value: {args.jitter}') if args.jitter else None
    # TBD: doesn't seem like it works as described below, so verify
    logger.log(f'* Ignoring jitter; sleep not set') if (args.jitter and not args.sleep) else None
    logger.log(f'* Timeout: {args.timeout}')
    logger.log(f'* User-Agent: {args.agent}') if args.agent else None
    logger.log(f'* Randomized IPs/ports') if args.randomize else None
    logger.log(f'* DNS mode / performing fwd/rev lookups prior to requests') if args.dns else None
    logger.log(f'* TEST mode / no requests or lookups sent') if args.test else None
    logger.log(f'* ---- </META> ---- *')
    logger.log(f"! ~~~ TEST MODE ~~~ !") if args.test else None

    ###########################
    # DNS lookups
    if args.dns:
        if args.test:
            logger.log(f" * skipping DNS lookups due to TEST mode")
        else:
            # reverse lookups
            for ip in ips:
                dns_rslt = ""
                try:
                    dns_rslt = socket.gethostbyaddr(ip)
                    logger.log(f" * DNS: {ip} --> {dns_rslt}", 'RSLT')
                except socket.herror as e:
                    logger.log(f" ! [Reverse DNS] Error resolving {ip}: {e}", 'DEBUG') # we expect failures here
                except socket.timeout:
                    logger.log(f" ! [Reverse DNS] Timeout resolving {ip}", 'ERROR')
                except Exception as e:
                    logger.log(f" ! [Reverse DNS] ERROR with {ip}: {e}", 'ERROR')
                jitter_val = random.uniform(0, args.jitter) if args.jitter else 0
                if (float(jitter_val + sleep_val) > 0):
                    time.sleep(sleep_val) # sleep between requests
            # fwd lookips
            for fqdn in valid_fqdns:
                dns_rslt = ""
                try:
                    dns_rslt = socket.gethostbyname_ex(fqdn)
                    logger.log(f" * DNS: {fqdn} --> {dns_rslt}", 'RSLT')
                except socket.gaierror as e:
                    logger.log(f" ! [Forward DNS] Error resolving {fqdn}: {e}", 'DEBUG')
                except socket.timeout:
                    logger.log(f" ! [Forward DNS] Timeout resolving {fqdn}", 'ERROR')
                except Exception as e:
                    logger.log(f" ! [Forward DNS] ERROR with {fqdn}: {e}", 'ERROR')
                jitter_val = random.uniform(0, args.jitter) if args.jitter else 0
                if (float(jitter_val + sleep_val) > 0):
                    time.sleep(sleep_val) # sleep between requests


    ###########################
    # Read FQDNs and loop for threads
    tests_tbd = []
    results = []
    future_origins = []
    prep_results = []
    future_preps = []
    sleep_val = args.sleep if args.sleep else 0
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # queue every combination of ip/port/fqdn
        for fqdn in valid_fqdns:
            for ip in ips:
                for port in ports:
                    tests_tbd.append(TestTarget(ip, port, fqdn))
        
	# TBD: option to display veryverbose?  or default value to trim this type of output, with option for 0 to show all?
        #logger.log(f"tests_tbd := {', '.join(f'[{tst.ip}, {tst.port}, {tst.fqdn}]' for tst in tests_tbd)}", 'DEBUG')
        logger.log(f"{len(tests_tbd)} potential test targets", 'DEBUG')
        # if we're doing the prep test, we send `GET /` with `Host: {ip}:{port}` header, and if we get any response that ip/port combo stays in the test queue
        if not args.no_prep:
            # find the unique ip/port combos in tests_tbd
            uniq_addrs = list({(tst.ip, tst.port) for tst in tests_tbd})
            #logger.log(f"uniq_addrs := {uniq_addrs}", 'DEBUG')
            random.shuffle(uniq_addrs) if args.randomize else None
            logger.log(f"{len(uniq_addrs)} unique address/port addresses for testing")
            # test with GET / to Host: {IP}:{port}
            with tqdm(total=len(uniq_addrs), desc='Prep Tests') as pbar_prep:
                for ip, port in uniq_addrs:
                    jitter_val = random.uniform(0, args.jitter) if args.jitter else 0
                    prep_id = random.choice(adjectives) + '_' + random.choice(nouns)
                    logger.log(f"  {prep_id} thread for {ip}:{port}", 'DEBUG')
                    future_preps.append(executor.submit(prep_thread_worker, ip, port, args.agent, args.test, args.timeout, args.verbose, prep_id, float(sleep_val + jitter_val)))
                for future in as_completed(future_preps):
                    result = future.result()
                    if result:
                        prep_results.append(result)
                        # if we don't already have this IP as an FQDN in tests_tbd, then queue it so we can review those results vs others w/ real FQDNs
                        if not any(t.ip == result.ip and t.port == result.port and t.fqdn == result.ip for t in tests_tbd):
                            #tqdm.write(f"  Adding prep result to testing queue with FQDN = IP for {result.ip}:{result.port}") if args.verbose else None
                            #tests_tbd.append(TestTarget(result.ip, result.port, result.ip))
                            tqdm.write(f"  Adding prep test response to results with FQDN = IP for {result.ip}:{result.port}") if args.verbose else None
                            results.append(TestResult(result.ip, result.ip, result.port, result.response))
                    pbar_prep.update(1)
            logger.log(f"{len(prep_results)} IP/ports verified, reducing test dataset from {len(tests_tbd)} entries")
            logger.log(f"prep_results := {', '.join(f'[{tst.ip}, {tst.port}, {tst.response}]' for tst in prep_results)}", 'DEBUG')
            # get the unique ip/port results from prep testing
            verified_hosts_set = set((result.ip, result.port) for result in prep_results)
            #logger.log(f"verified_hosts_set := {verified_hosts_set}", 'DEBUG')
            # rebuild tests_tbd with just the ips / ports discovered as live
            tests_tbd = [row for row in tests_tbd if (row.ip, row.port) in verified_hosts_set]
            logger.log(f"{len(tests_tbd)} pending tests remain after pre-testing")

        logger.log(f"tests_tbd := {', '.join(f'[{tst.ip}, {tst.port}, {tst.fqdn}]' for tst in tests_tbd)}", 'DEBUG')
        random.shuffle(tests_tbd) if args.randomize else None

        total_tests = len(tests_tbd)
        logger.log(f"Queuing {total_tests} threads")
        # send `GET /` with `Host: {fqdn}` to {ip}:{port}, and record any response
        with tqdm(total=total_tests, desc='Origin Scan') as pbar:
            for test in tests_tbd:
                jitter_val = random.uniform(0, args.jitter) if args.jitter else 0
                thread_id = random.choice(adjectives) + '_' + random.choice(nouns)
                logger.log(f"  {thread_id} thread for {test.ip}:{test.port} using host {test.fqdn}", 'DEBUG')
                future_origins.append(executor.submit(thread_worker, test.ip, test.port, test.fqdn, args.agent, args.test, args.timeout, args.verbose, thread_id, float(sleep_val + jitter_val)))
            for future in as_completed(future_origins):
                result = future.result() 
                results.append(result) if result else None
                pbar.update(1)

    ###########################
    # parse results
    if len(results) == 0:
        logger.log("No Results", 'WARN')
    else:
        fqdn_results = {}
        rslt_output = ""
        current_date = datetime.datetime.utcnow()
        csv_first_row = True
        for rslt in results:
            # group results by FDQN (per robotic advice)
            fqdn_results.setdefault(rslt.fqdn, []).append(rslt)
            # handle CSV output
            if args.csv:
                with open(csv_file, mode='a', newline='') as csv_output_file:
                    csv_writer = csv.writer(csv_output_file)
                    if not csv_first_row:
                        header_str = ""
                        #delimiter = '~~#~~'
                        delimiter = '\n'
                        for name, value in rslt.response.headers.items():
                            header_str += f"{name}: {value}{delimiter}"
                        header_str = header_str.rstrip(delimiter)
                        csv_writer.writerow([rslt.fqdn, rslt.ip, rslt.port, rslt.response.status_code, rslt.response.reason, header_str, get_response_content_summary(rslt.response)])
                    else:
                        # Write the header row
                        csv_writer.writerow(['FQDN', 'IP', 'Port', 'Status', 'Reason', 'Headers', 'Response'])
                        header_str = ""
                        # TBD: make this an option, or move it up top
                        #delimiter = '~~#~~'
                        delimiter = '\n'
                        for name, value in rslt.response.headers.items():
                            header_str += f"{name}: {value}{delimiter}"
                        header_str = header_str.rstrip(delimiter)
                        csv_writer.writerow([rslt.fqdn, rslt.ip, rslt.port, rslt.response.status_code, rslt.response.reason, header_str, get_response_content_summary(rslt.response)])
                        csv_first_row = False
        # prep and display summary of results
        for fqdn, results in fqdn_results.items():
            rslt_output += f"  {fqdn}\n"
            for r in results:
                if (r.response.status_code // 100 == 3):
                    # trim the 3xx location for display
                    resp_loc = r.response.headers['Location']
                    if len(resp_loc) > 100:
                        resp_loc = f"{resp_loc[0:99]}..."
                    rslt_output += f"    {r.ip}:{r.port} => ({r.response.status_code} / {r.response.reason}) ==> {resp_loc}\n"
                else:
                    rslt_output += f"    {r.ip}:{r.port} => ({r.response.status_code} / {r.response.reason})\n"
            rslt_output += "\n"
        logger.log(f"Results from {len(fqdn_results.items())} FQDNs:\n{rslt_output}", 'RSLT')

if __name__ == "__main__":
    main()

