# DoHound 🐾  
_Asynchronous Subdomain Enumerator_

## Overview
DoHound is a fast and simple tool for discovering subdomains.  
It gathers results from [crt.sh](https://crt.sh/) and optionally brute-forces additional subdomains using a wordlist.  
All lookups are performed asynchronously for speed, with colored output and optional saving to a file.

## Features
- Fetch subdomains from **crt.sh**
- Optional brute-force using a custom wordlist
- Concurrent DNS resolution with retries
- Progress bars for long runs
- Colored, human-friendly output

## Requirements
- Python **3.8**
- System: Linux / MacOS / Windows
- Dependencies:
  ```bash
  pip install aiohttp colorama tqdm
  ```

## Usage
Basic usage:
```bash
python3 DoHound.py -u example.com
```

Save results to file:
```bash
python3 DoHound.py -u example.com -o subs.txt
```

Brute-force with wordlist:
```bash
python3 DoHound.py -u example.com -w wordlist.txt -o found.txt
```

Common options:
```
-u, --url        Target domain (required)
-w, --wordlist   Path to wordlist file
--crt-only       Only fetch from crt.sh
--brute-only     Only brute-force
-o, --output     Save results to this file
--concurrency    Max concurrent DNS requests (default: 50)
--timeout        HTTP request timeout in seconds (default: 5)
--retries        DNS retries per subdomain (default: 2)
```

## Example Output
```
[CRT] blog.example.com -> 203.0.113.45
[CRT] shop.example.com -> No IP
[BRUTE] admin.example.com -> 203.0.113.89
```

## Notes
- Results are **not saved by default**. Use `-o` to write them to a file.
- High concurrency values may cause rate limits or dropped DNS queries.
- Intended for **authorized security testing and research only**.

## License
MIT License.

