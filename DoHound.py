#!/usr/bin/env python3
import argparse
import asyncio
import socket
import aiohttp
import subprocess
import logging
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# -------------------------------
# FIGLET BANNER
# -------------------------------
def print_banner(text):
    try:
        banner = subprocess.check_output(["figlet", text], text=True)
        print(Fore.CYAN + banner)
    except Exception as e:
        print(f"{Fore.RED}[!] Could not print banner: {e}")

# -------------------------------
# LOGGING SETUP
# -------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("DoHound")

# -------------------------------
# ASYNC DNS RESOLVER WITH RETRY
# -------------------------------
async def resolve_ip(subdomain, loop, retries=2):
    """
    Attempt to resolve subdomain to IP using getaddrinfo.
    Returns (subdomain, ip_or_None).
    """
    for attempt in range(1, retries + 1):
        try:
            info = await loop.getaddrinfo(subdomain, None)
            ip = info[0][4][0]
            return subdomain, ip
        except Exception as e:
            
            if attempt == retries:
                return subdomain, None
            await asyncio.sleep(0.3) 

# -------------------------------
# FETCH SUBDOMAINS FROM CRT.SH
# -------------------------------
async def fetch_crtsh(domain, http_timeout):
    logger.info(f"Searching crt.sh for subdomains of {domain}...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subs = set()
    timeout = aiohttp.ClientTimeout(total=http_timeout)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.warning(f"crt.sh returned HTTP {resp.status}")
                    return []
                data = await resp.json()
                for entry in data:
                    names = entry.get("name_value", "")
                    for sub in names.split("\n"):
                        sub = sub.strip()
                        if not sub:
                            continue
                        
                        if sub.endswith(domain):
                            subs.add(sub)
        except Exception as e:
            logger.error(f"Error fetching crt.sh: {e}")
    return sorted(subs)

# -------------------------------
# ASYNC RESOLVE WITH CONCURRENCY & PROGRESS
# -------------------------------
async def resolve_list(subdomains, loop, concurrency=50, retries=2, label="Resolving"):
    """
    Resolve subdomains concurrently with a semaphore and show progress using tqdm.
    Returns list of tuples (subdomain, ip_or_None)
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_resolve(sub):
        async with semaphore:
            return await resolve_ip(sub, loop, retries=retries)

    tasks = [asyncio.create_task(sem_resolve(s)) for s in subdomains]
    results = []
    # Use asyncio.as_completed to update progress bar as tasks finish
    for fut in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=label, unit="sub"):
        try:
            res = await fut
            results.append(res)
        except Exception as e:
            logger.debug(f"Task exception: {e}")
            results.append((None, None))
    return results

# -------------------------------
# BRUTE-FORCE WORDLIST
# -------------------------------
async def brute_from_wordlist(domain, words, loop, concurrency=50, retries=2):
    subs = [f"{w}.{domain}" for w in words]
    resolved = await resolve_list(subs, loop, concurrency=concurrency, retries=retries, label="Brute-forcing")
    valid = []
    for sub, ip in resolved:
        if ip:
            print(f"{Fore.YELLOW}[BRUTE]{Style.RESET_ALL} {sub} -> {ip}")
            valid.append((sub, ip))
    return valid

# -------------------------------
# MAIN FUNCTION
# -------------------------------
async def main():
    # --- Banner ---
    print_banner("DoHound")
    print(Fore.CYAN + "[+] Async Subdomain Enumerator")
    print(Fore.CYAN + "[+] Author: Huseynov Suleyman | GitHub: github.com/huseyn0vs/DoHound")

    # --- Argument Parser ---
    parser = argparse.ArgumentParser(description="DoHound - Async Subdomain Enumerator")
    parser.add_argument("-u", "--url", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("--crt-only", action="store_true", help="Only fetch subdomains from crt.sh")
    parser.add_argument("--brute-only", action="store_true", help="Only brute-force using wordlist")
    parser.add_argument("-o", "--output", default=None, help="Output file name")
    parser.add_argument("--concurrency", type=int, default=50, help="Max concurrent DNS requests (default: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--retries", type=int, default=2, help="DNS resolve retry attempts (default: 2)")

    args = parser.parse_args()

    domain = args.url.strip()
    loop = asyncio.get_event_loop()
    found = []  # list of (sub, ip_or_None) or strings for final formatting

    # --- CRT.SH SUBDOMAINS ---
    if args.crt_only or (not args.crt_only and not args.brute_only):
        crt_subs = await fetch_crtsh(domain, http_timeout=args.timeout)
        if crt_subs:
            crt_results = await resolve_list(crt_subs, loop, concurrency=args.concurrency, retries=args.retries, label="Resolving CRT subs")
            for sub, ip in sorted(crt_results):
                if sub is None:
                    continue
                if ip:
                    print(f"{Fore.GREEN}[CRT]{Style.RESET_ALL} {sub} -> {ip}")
                    found.append((sub, ip))
                else:
                    print(f"{Fore.RED}[CRT]{Style.RESET_ALL} {sub} -> No IP")
                    found.append((sub, None))
        else:
            logger.info("No results from crt.sh or failed to fetch.")

    # --- BRUTE FORCE ---
    if (args.brute_only or (not args.crt_only and not args.brute_only)) and args.wordlist:
        try:
            with open(args.wordlist, "r") as f:
                words = [w.strip() for w in f if w.strip()]
            brute_valid = await brute_from_wordlist(domain, words, loop, concurrency=args.concurrency, retries=args.retries)
            found.extend(brute_valid)
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {args.wordlist}")
        except Exception as e:
            logger.error(f"Error reading wordlist: {e}")

    # --- Dedupe and Sort ---
    summary = {}
    for sub, ip in found:
        if sub is None:
            continue
        if sub not in summary or (summary[sub] is None and ip is not None):
            summary[sub] = ip
    all_subs = sorted(summary.items(), key=lambda x: x[0])

    # --- Output (ONLY if -o provided) ---
    if args.output:
        try:
            with open(args.output, "w") as f:
                for sub, ip in all_subs:
                    line = f"{sub} -> {ip}" if ip else f"{sub} -> No IP"
                    f.write(line + "\n")
            logger.info(f"Done! Saved {len(all_subs)} subdomains to {args.output}")
        except Exception as e:
            logger.error(f"Failed to write to output file {args.output}: {e}")
    else:
        logger.info(f"Done! Found {len(all_subs)} subdomains (not saved). Use -o to save to file.")
        
        for sub, ip in all_subs:
            if ip:
                print(f"{Fore.MAGENTA}{sub}{Style.RESET_ALL} -> {ip}")
            else:
                print(f"{Fore.MAGENTA}{sub}{Style.RESET_ALL} -> {Fore.RED}No IP{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")

