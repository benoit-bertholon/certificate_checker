# Certificate Checker

helper:

```
$ python3 check_certif.py  -h
usage: check_certif.py [-h] [-u URLS] [-f FILE] [-w WARNING]

SSL Check

optional arguments:
  -h, --help            show this help message and exit
  -u URLS, --url URLS   url to check (default: [])
  -f FILE, --file FILE  file with urls (one per line) (default: None)
  -w WARNING, --warning WARNING
                        display warning if the number of days is lower than
                        this value (default: 10)
```

```
$ python3 check_certif.py  -u google.com
[OK]: the SSL cerfificate of google.com expires in 47 days
```
