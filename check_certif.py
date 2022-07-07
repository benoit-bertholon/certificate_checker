import ssl
import OpenSSL
import dateutil.parser as dateparser
import argparse
import datetime
import socket
import os

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def get_time_end(url_arg):
    many = url_arg.split(":")
    if len(many) > 1:
        url, port = many[0],int(many[1])
    else:
        url, port = many[0], 443
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.load_default_certs()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=url)
    try:
        ssl_sock.connect((url,port))
        ssl_sock.do_handshake()
    except Exception as e:
        return str(e)
    ssl_sock.context.get_ciphers()
    cert = ssl_sock.getpeercert()
    status = False
    possible = []
    for submain in (cert['subject']):
      for sub in submain:
        if sub[0] == "commonName":
          possible.append(sub[1])
          if sub[1] == url:
            status = True
          if sub[1].split(".")[0] == "*":
            if ".".join(sub[1].split(".")[1:]) == ".".join(url[1].split(".")[1:]):
              status = True
    for sub in (cert["subjectAltName"]):
        if sub[0] == "DNS":
          possible.append(sub[1])
          if sub[1] == url:
            status = True
          if sub[1].split(".")[0] == "*":
            if ".".join(sub[1].split(".")[1:]) == ".".join(url.split(".")[1:]):
              status = True
    if status:
      return dateparser.parse(cert["notAfter"])
    return "not good url: "+",".join(possible)

    


if __name__ == "__main__" :
    parser = argparse.ArgumentParser(description='SSL Check', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-u','--url', dest='urls', default=[], action="append", help="url to check")
    parser.add_argument('-f','--file', dest='file', default=None, help="file with urls (one per line)")
    parser.add_argument('-w','--warning', dest='warning', default=10, type=int, help="display warning if the number of days is lower than this value")
    args = parser.parse_args()
    
    urls = args.urls
    
    if args.file is not None:
        if not os.path.isfile(args.file):
            raise Exception("file does not exists: %s".args.file)
        with open(args.file,"r") as f:
            unfiltred = list(map(lambda x:x.strip(), f.read().splitlines()))
            urls += list(filter(lambda x:x != "",unfiltred))
    
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    for url in urls:
        t = get_time_end(url)
        if type(t) is str:
            print(f"[{FAIL}ERROR{ENDC}]: the SSL cerfificate of {FAIL}{url}{ENDC} is not valid: {t}")
            continue
        diff = t - now

        if diff < datetime.timedelta(10):
            print(f"[{WARNING}WARNING{ENDC}]: the SSL cerfificate of {WARNING}{url}{ENDC} expires in {diff.days} days")
        else:
            print(f"[{OKGREEN}OK{ENDC}]: the SSL cerfificate of {url} expires in {diff.days} days" )

