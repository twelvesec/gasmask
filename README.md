## gasmask

All in one Information gathering tool - OSINT

Written by: [maldevel](https://github.com/maldevel) ([twitter](https://twitter.com/maldevel))

---

### Dependencies

* Python 2.x
* validators
* python-whois
* dnspython
* requests

### Information Gathering

* ask
* bing
* crt
* dns
* dnsdumpster
* dogpile
* github
* google
* googleplus
* instagram
* linkedin
* netcraft
* pgp
* reddit
* reverse dns
* twitter
* vhosts
* virustotal
* whois
* yahoo
* yandex
* youtube

---

### Dependencies

```
sudo pip install -r requirements.txt
```

---

### Usage

```
    ______           __  ___           __ __
  / ____/___ ______/  |/  /___ ______/ //_/
 / / __/ __ `/ ___/ /|_/ / __ `/ ___/ ,<
/ /_/ / /_/ (__  ) /  / / /_/ (__  ) /| |
\____/\__,_/____/_/  /_/\__,_/____/_/ |_|

GasMasK - All in one Information gathering tool - OSINT
Ver. 1.0
Written by: @maldevel
https://www.twelvesec.com/

usage: gasmask.py [-h] -d DOMAIN [-s NAMESERVER] [-x PROXY] [-l LIMIT]
                  [-i MODE] [-o BASENAME]

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain to search.
  -s NAMESERVER, --server NAMESERVER
                        DNS server to use.
  -x PROXY, --proxy PROXY
                        Use a proxy server when retrieving results from search engines (eg. '-x http://127.0.0.1:8080')
  -l LIMIT, --limit LIMIT
                        Limit the number of search engine results (default: 100)                                                          .
  -i MODE, --info MODE  Limit information gathering (basic,whois,dns,revdns,vhosts,google,bing,yahoo,ask,dogpile,yandex,linkedin,twitter,googleplus,youtube,reddit,github,instagram,crt,pgp,netcraft,virustotal,dnsdump).
  -o BASENAME, --output BASENAME
                        Output in the four major formats at once (markdown, txt, xml and html).

```

---

### Usage Examples

```
python gasmask.py -d example.com -i basic

python gasmask.py -d example.com -i dnsdump

python gasmask.py -d example.com -i whois,dns,revdns

python gasmask.py -d example.com -i basic,yahoo,github -o myresults/example_com_search_results
```

---

### Credits

* [EmailHarvester](https://github.com/maldevel/EmailHarvester)
* [theHarvester](https://github.com/laramies/theHarvester)
* [Sublist3r](https://github.com/aboul3la/Sublist3r)

---
