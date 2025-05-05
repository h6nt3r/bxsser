#!/usr/bin/env python3
import os
import re
import time
import sys
import argparse
import urllib.parse
import base64
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import signal

# Thread-safe queue for printing to avoid interleaved output
print_queue = Queue()
print_lock = threading.Lock()

def thread_safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)
        sys.stdout.flush()

def handle_exit(signum, frame):
    thread_safe_print("\n\033[0;31m[!] Program interrupted. Exiting...\033[0m")
    sys.exit(1)

def encode_payload(payload, encoding_type):
    if encoding_type == "url":
        return urllib.parse.quote(payload)
    elif encoding_type == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding_type == "ascii":
        return ''.join([str(ord(c)) for c in payload])
    return payload  # No encoding if none specified

def set_random_user_agent_and_preferences(options):
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0"
    ]
    random_user_agent = random.choice(user_agents)
    options.add_argument(f"user-agent={random_user_agent}")

    timezones = [
        "America/New_York",
        "Europe/London",
        "Asia/Kolkata",
        "Australia/Sydney",
        "Africa/Johannesburg"
    ]
    random_timezone = random.choice(timezones)
    options.add_experimental_option("prefs", {"intl.accept_languages": "en-US,en;q=0.9"})
    options.add_argument(f"--lang=en-US")
    options.add_argument(f"--timezone={random_timezone}")

    screen_sizes = [
        "1920,1080",
        "1366,768",
        "1536,864",
        "1280,720",
        "1440,900"
    ]
    random_screen_size = random.choice(screen_sizes)
    width, height = random_screen_size.split(",")
    options.add_argument(f"--window-size={width},{height}")

    referrers = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://www.yahoo.com/",
        "https://www.facebook.com/",
        "https://twitter.com/"
    ]
    random_referrer = random.choice(referrers)
    options.add_argument(f"--referer={random_referrer}")

    languages = [
        "en-US",
        "es-ES",
        "fr-FR",
        "de-DE",
        "it-IT",
        "pt-BR",
        "ja-JP",
        "zh-CN",
        "ru-RU"
    ]
    random_language = random.choice(languages)
    options.add_argument(f"--lang={random_language}")

def extract_query_parameter_name(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return query_params

def display_welcome_message():
    created_by_text = "Program created by: h6nt3r, and inspired by AnonKryptiQuz"
    ascii_width = 45
    padding = (ascii_width - len(created_by_text)) // 2
    thread_safe_print(" " * padding + f"\033[0;31m{created_by_text}\033[0m")
    thread_safe_print("")

def is_valid_url(url):
    url_pattern = r"^(http|https)://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})(/.*)?$"
    return re.match(url_pattern, url) is not None

def load_payloads(payload_file):
    if not os.path.isfile(payload_file):
        thread_safe_print(f"\033[0;31m[!] Payload file {payload_file} does not exist.\033[0m")
        sys.exit(1)
    with open(payload_file, 'r') as file:
        payloads = [line.strip() for line in file if line.strip()]
    if not payloads:
        thread_safe_print(f"\033[0;31m[!] Payload file {payload_file} is empty.\033[0m")
        sys.exit(1)
    return payloads

def check_xss_vulnerability(base_url, driver, encoding_type, vulnerable_urls, payloads, url_index, total_urls):
    parsed_url = urlparse(base_url)
    query_params = parse_qs(parsed_url.query)
    base_url_no_query = base_url.split('?')[0]

    if not query_params:
        thread_safe_print(f"\033[0;31m[!] URL skipped: No query parameters found: {base_url}\033[0m")
        return

    total_payloads = len(payloads)
    injection_params = {param: values for param, values in query_params.items() if any("*" in v for v in values)}
    params_to_scan = injection_params if injection_params else query_params

    if not params_to_scan:
        thread_safe_print(f"\033[0;31m[!] URL skipped: No parameters to scan: {base_url}\033[0m")
        return

    total_params = len(params_to_scan)

    for param_index, (param_name, param_values) in enumerate(params_to_scan.items(), start=1):
        for param_value in param_values:
            if "*" in param_value:
                for index, payload in enumerate(payloads, start=1):
                    encoded_payload = encode_payload(payload, encoding_type)

                    final_value = param_value.replace("*", encoded_payload)
                    modified_query_params = query_params.copy()
                    modified_query_params[param_name] = [final_value]
                    full_url = f"{base_url_no_query}?{'&'.join([f'{key}={urllib.parse.quote(value[0])}' for key, value in modified_query_params.items()])}"

                    thread_safe_print(f"\033[0;35m[i] Parameter({param_index}/{total_params}): \033[0m\033[0;37m{param_name}\033[0m")
                    thread_safe_print(f"\033[0;35m[i] Payload({index}/{total_payloads}): \033[0m\033[0;37m{payload}\033[0m")
                    thread_safe_print(f"\033[0;35m[i] Payload Encoded ({encoding_type or 'none'}): \033[0m\033[0;37m{encoded_payload}\033[0m")
                    thread_safe_print(f"\033[0;36m[i] URL({url_index}/{total_urls}): \033[0m\033[0;37m{full_url}\033[0m")

                    try:
                        driver.get(full_url)
                        time.sleep(3)
                        if "xss.report" in driver.page_source:
                            with threading.Lock():
                                vulnerable_urls.append(full_url)
                    except Exception as e:
                        thread_safe_print(f"\033[0;31m[!] Error accessing URL {full_url}: {e}\033[0m")

                    thread_safe_print()
            elif not injection_params:
                for index, payload in enumerate(payloads, start=1):
                    encoded_payload = encode_payload(payload, encoding_type)

                    modified_query_params = query_params.copy()
                    modified_query_params[param_name] = [encoded_payload]
                    full_url = f"{base_url_no_query}?{'&'.join([f'{key}={urllib.parse.quote(value[0])}' for key, value in modified_query_params.items()])}"

                    thread_safe_print(f"\033[0;35m[i] Parameter({param_index}/{total_params}): \033[0m\033[0;37m{param_name}\033[0m")
                    thread_safe_print(f"\033[0;35m[i] Payload({index}/{total_payloads}): \033[0m\033[0;37m{payload}\033[0m")
                    thread_safe_print(f"\033[0;35m[i] Payload Encoded ({encoding_type or 'none'}): \033[0m\033[0;37m{encoded_payload}\033[0m")
                    thread_safe_print(f"\033[0;36m[i] URL({url_index}/{total_urls}): \033[0m\033[0;37m{full_url}\033[0m")

                    try:
                        driver.get(full_url)
                        time.sleep(3)
                        if "xss.report" in driver.page_source:
                            with threading.Lock():
                                vulnerable_urls.append(full_url)
                    except Exception as e:
                        thread_safe_print(f"\033[0;31m[!] Error accessing URL {full_url}: {e}\033[0m")

                    thread_safe_print()

def process_url(base_url, encoding_type, vulnerable_urls, payloads, url_index, total_urls):
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument("--disable-gpu")
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-infobars')
    options.add_argument('--disable-default-apps')
    set_random_user_agent_and_preferences(options)

    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        check_xss_vulnerability(base_url, driver, encoding_type, vulnerable_urls, payloads, url_index, total_urls)
        driver.quit()
    except Exception as e:
        thread_safe_print(f"\033[0;31m[!] Error processing URL {base_url}: {e}\033[0m")

def scan_urls_from_file(file_path, encoding_type, vulnerable_urls, payloads, num_threads):
    if not os.path.isfile(file_path):
        thread_safe_print(f"\033[0;31m[!] URL file {file_path} does not exist.\033[0m")
        sys.exit(1)
    valid_urls = []
    with open(file_path, 'r') as file:
        for line in file:
            base_url = line.strip()
            if not base_url:
                continue
            if is_valid_url(base_url):
                query_params = extract_query_parameter_name(base_url)
                if query_params:
                    valid_urls.append(base_url)
            else:
                thread_safe_print(f"\033[0;31m[!] Invalid URL skipped: {base_url}\033[0m")
    
    total_urls = len(valid_urls)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_url, base_url, encoding_type, vulnerable_urls, payloads, index, total_urls)
            for index, base_url in enumerate(valid_urls, start=1)
        ]
        for future in futures:
            future.result()  # Wait for all threads to complete
    
    return valid_urls

def scan_urls_from_stdin(encoding_type, vulnerable_urls, payloads, num_threads):
    valid_urls = []
    if sys.stdin.isatty():
        thread_safe_print("\033[0;37m[?] Enter URLs (one per line, press Ctrl+D or empty line to finish):\033[0m")
        lines = []
        while True:
            try:
                line = input()
                if not line:
                    break
                lines.append(line)
            except EOFError:
                break
    else:
        lines = sys.stdin.readlines()

    for line in lines:
        base_url = line.strip()
        if not base_url:
            continue
        if is_valid_url(base_url):
            query_params = extract_query_parameter_name(base_url)
            if query_params:
                valid_urls.append(base_url)
        else:
            thread_safe_print(f"\033[0;31m[!] Invalid URL skipped: {base_url}\033[0m")

    total_urls = len(valid_urls)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_url, base_url, encoding_type, vulnerable_urls, payloads, index, total_urls)
            for index, base_url in enumerate(valid_urls, start=1)
        ]
        for future in futures:
            future.result()  # Wait for all threads to complete
    
    return valid_urls

def scan_single_url(url, encoding_type, vulnerable_urls, payloads):
    valid_urls = []
    if is_valid_url(url):
        query_params = extract_query_parameter_name(url)
        if query_params:
            valid_urls.append(url)
            process_url(url, encoding_type, vulnerable_urls, payloads, 1, 1)
        else:
            thread_safe_print(f"\033[0;31m[!] URL skipped: No query parameters found: {url}\033[0m")
    else:
        thread_safe_print(f"\033[0;31m[!] Invalid URL skipped: {url}\033[0m")
    return valid_urls

def main():
    parser = argparse.ArgumentParser(description="Blind XSS Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="File containing URLs to scan (default: read from stdin)")
    group.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-p", "--payloads", required=True, help="File containing XSS payloads")
    parser.add_argument("-e", "--encode", choices=["url", "base64", "ascii"], default=None, help="Encoding type for payloads (url, base64, ascii; default: none)")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads for parallel processing (default: 1)")
    args = parser.parse_args()

    if args.threads < 1:
        thread_safe_print("\033[0;31m[!] Number of threads must be at least 1.\033[0m")
        sys.exit(1)

    display_welcome_message()

    payloads = load_payloads(args.payloads)
    thread_safe_print(f"\033[1;34m[i] Loaded {len(payloads)} payloads from {args.payloads}\033[0m")
    thread_safe_print(f"\033[1;34m[i] Using {args.threads} thread(s) for scanning\033[0m")
    if args.encode:
        thread_safe_print(f"\033[1;34m[i] Encoding payloads with {args.encode}\033[0m")

    thread_safe_print("\n\033[1;33m[i] Loading, Please Wait...\033[0m")
    time.sleep(3)

    thread_safe_print("\033[1;34m[i] Starting BXSS vulnerability check\033[0m")
    thread_safe_print("\033[1;36m[i] Starting Web Driver(s), Please wait...\033[0m\n")

    start_time = time.time()
    vulnerable_urls = []

    if args.url:
        valid_urls = scan_single_url(args.url, args.encode, vulnerable_urls, payloads)
    elif args.file:
        valid_urls = scan_urls_from_file(args.file, args.encode, vulnerable_urls, payloads, args.threads)
    else:
        valid_urls = scan_urls_from_stdin(args.encode, vulnerable_urls, payloads, args.threads)

    total_scanned = len(valid_urls)

    elapsed_time = time.time() - start_time
    thread_safe_print(f"\033[1;33m[i] Scan finished!\033[0m")
    thread_safe_print(f"\033[1;33m[i] Total URLs Scanned: {total_scanned}\033[0m")
    thread_safe_print(f"\033[1;33m[i] Time Taken: {int(elapsed_time)} seconds.\033[0m\n")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit)
    main()