#!/usr/bin/env python3
import os
import re
import time
import sys
import argparse
import urllib.parse
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import random
import traceback

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
    print(" " * padding + f"\033[0;31m{created_by_text}\033[0m")
    print("")

def is_valid_url(url):
    url_pattern = r"^(http|https)://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})(/.*)?$"
    return re.match(url_pattern, url) is not None

def load_payloads(payload_file):
    if not os.path.isfile(payload_file):
        print(f"\033[0;31m[!] Payload file {payload_file} does not exist.\033[0m")
        sys.exit(1)
    with open(payload_file, 'r') as file:
        payloads = [line.strip() for line in file if line.strip()]
    if not payloads:
        print(f"\033[0;31m[!] Payload file {payload_file} is empty.\033[0m")
        sys.exit(1)
    return payloads

def check_xss_vulnerability(base_url, driver, encode_times, vulnerable_urls, payloads, url_index, total_urls, debug=False, require_star=False):
    parsed_url = urlparse(base_url)
    query_params = parse_qs(parsed_url.query)
    base_url_no_query = base_url.split('?')[0]

    if debug:
        print(f"\033[0;33m[DEBUG] Processing URL: {base_url}\033[0m")
        print(f"\033[0;33m[DEBUG] Query Parameters: {query_params}\033[0m")

    if not query_params:
        print(f"\033[0;31m[!] URL skipped: No query parameters found: {base_url}\033[0m")
        if debug:
            print(f"\033[0;33m[DEBUG] No query parameters found, skipping URL\033[0m")
        return

    # Total number of payloads
    total_payloads = len(payloads)

    # Find parameters with * injection point
    injection_params = {param: values for param, values in query_params.items() if any("*" in v for v in values)}

    if debug:
        print(f"\033[0;33m[DEBUG] Parameters with *: {injection_params}\033[0m")

    # Determine which parameters to scan
    params_to_scan = injection_params if injection_params else ({} if require_star else query_params)

    if not params_to_scan:
        print(f"\033[0;31m[!] URL skipped: No * found in query parameters: {base_url}\033[0m")
        if debug:
            print(f"\033[0;33m[DEBUG] No * found in query parameters\033[0m")
        return

    # Total number of parameters to scan
    total_params = len(params_to_scan)

    # Process parameters (either * marked or all if no * and require_star is False)
    for param_index, (param_name, param_values) in enumerate(params_to_scan.items(), start=1):
        for param_value in param_values:
            if "*" in param_value:
                # Handle * marked parameters
                for index, payload in enumerate(payloads, start=1):
                    for encode_step in range(encode_times + 1):
                        encoded_payload = payload
                        for _ in range(encode_step):
                            encoded_payload = urllib.parse.quote(encoded_payload)

                        # Replace * with the encoded payload
                        final_value = param_value.replace("*", encoded_payload)

                        # Construct the modified query string
                        modified_query_params = query_params.copy()
                        modified_query_params[param_name] = [final_value]
                        full_url = f"{base_url_no_query}?{'&'.join([f'{key}={urllib.parse.quote(value[0])}' for key, value in modified_query_params.items()])}"

                        print(f"\033[0;35m[i] Parameter({param_index}/{total_params}): \033[0m\033[0;37m{param_name}\033[0m")
                        print(f"\033[0;35m[i] Payload({index}/{total_payloads}): \033[0m\033[0;37m{payload}\033[0m")
                        print(f"\033[0;35m[i] Payload Encoded {encode_step}-{encode_times} times: \033[0m\033[0;37m{encoded_payload}\033[0m")
                        print(f"\033[0;36m[i] URL({url_index}/{total_urls}): \033[0m\033[0;37m{full_url}\033[0m")

                        try:
                            driver.get(full_url)
                            time.sleep(3)
                            if "xss.report" in driver.page_source:
                                vulnerable_urls.append(full_url)
                        except Exception as e:
                            print(f"\033[0;31m[!] Error accessing URL {full_url}: {e}\033[0m")
                            if debug:
                                print(f"\033[0;33m[DEBUG] Exception details: {traceback.format_exc()}\033[0m")

                        # Add a new line after each scan
                        print()
            else:
                # Handle non-* parameters (when require_star is False)
                for index, payload in enumerate(payloads, start=1):
                    for encode_step in range(encode_times + 1):
                        encoded_payload = payload
                        for _ in range(encode_step):
                            encoded_payload = urllib.parse.quote(encoded_payload)

                        # Replace the entire parameter value with the encoded payload
                        modified_query_params = query_params.copy()
                        modified_query_params[param_name] = [encoded_payload]
                        full_url = f"{base_url_no_query}?{'&'.join([f'{key}={urllib.parse.quote(value[0])}' for key, value in modified_query_params.items()])}"

                        print(f"\033[0;35m[i] Parameter({param_index}/{total_params}): \033[0m\033[0;37m{param_name}\033[0m")
                        print(f"\033[0;35m[i] Payload({index}/{total_payloads}): \033[0m\033[0;37m{payload}\033[0m")
                        print(f"\033[0;35m[i] Payload Encoded {encode_step}-{encode_times} times: \033[0m\033[0;37m{encoded_payload}\033[0m")
                        print(f"\033[0;36m[i] URL({url_index}/{total_urls}): \033[0m\033[0;37m{full_url}\033[0m")

                        try:
                            driver.get(full_url)
                            time.sleep(3)
                            if "xss.report" in driver.page_source:
                                vulnerable_urls.append(full_url)
                        except Exception as e:
                            print(f"\033[0;31m[!] Error accessing URL {full_url}: {e}\033[0m")
                            if debug:
                                print(f"\033[0;33m[DEBUG] Exception details: {traceback.format_exc()}\033[0m")

                        # Add a new line after each scan
                        print()

def save_results_to_file(vulnerable_urls, output_file):
    if not output_file:
        return
    try:
        print(f"\033[1;33m[i] Saving results to {output_file}...\033[0m")
        with open(output_file, 'w') as file:
            for url in vulnerable_urls:
                file.write(f"{url}\n")
        print(f"\033[0;32m[i] Results saved to {output_file}\033[0m")
    except Exception as e:
        print(f"\033[0;31m[!] Error saving results to {output_file}: {e}\033[0m")

def handle_exit(signum, frame):
    print("\n\033[0;31m[!] Program interrupted. Exiting...\033[0m")
    sys.exit(1)

def scan_urls_from_file(file_path, driver, encode_times, vulnerable_urls, payloads, debug=False, require_star=False):
    if not os.path.isfile(file_path):
        print(f"\033[0;31m[!] URL file {file_path} does not exist.\033[0m")
        sys.exit(1)
    valid_urls = []
    # First pass: Collect valid URLs with query parameters
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
                print(f"\033[0;31m[!] Invalid URL skipped: {base_url}\033[0m")
    
    total_urls = len(valid_urls)
    for index, base_url in enumerate(valid_urls, start=1):
        check_xss_vulnerability(base_url, driver, encode_times, vulnerable_urls, payloads, index, total_urls, debug, require_star)
    
    return valid_urls

def scan_urls_from_stdin(driver, encode_times, vulnerable_urls, payloads, debug=False, require_star=False):
    valid_urls = []
    if sys.stdin.isatty():
        print("\033[0;37m[?] Enter URLs (one per line, press Ctrl+D or empty line to finish):\033[0m")
        # Collect all URLs first for interactive input
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

    # First pass: Collect valid URLs with query parameters
    for line in lines:
        base_url = line.strip()
        if not base_url:
            continue
        if is_valid_url(base_url):
            query_params = extract_query_parameter_name(base_url)
            if query_params:
                valid_urls.append(base_url)
        else:
            print(f"\033[0;31m[!] Invalid URL skipped: {base_url}\033[0m")

    total_urls = len(valid_urls)
    for index, base_url in enumerate(valid_urls, start=1):
        check_xss_vulnerability(base_url, driver, encode_times, vulnerable_urls, payloads, index, total_urls, debug, require_star)
    
    return valid_urls

def scan_single_url(url, driver, encode_times, vulnerable_urls, payloads, debug=False, require_star=False):
    valid_urls = []
    if is_valid_url(url):
        query_params = extract_query_parameter_name(url)
        if query_params:
            valid_urls.append(url)
            # Single URL, so total_urls is 1
            check_xss_vulnerability(url, driver, encode_times, vulnerable_urls, payloads, 1, 1, debug, require_star)
        else:
            print(f"\033[0;31m[!] URL skipped: No query parameters found: {url}\033[0m")
    else:
        print(f"\033[0;31m[!] Invalid URL skipped: {url}\033[0m")
    return valid_urls

def main():
    parser = argparse.ArgumentParser(description="Blind XSS Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="File containing URLs to scan (default: read from stdin)")
    group.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-p", "--payloads", required=True, help="File containing XSS payloads")
    parser.add_argument("-e", "--encode", type=int, default=0, choices=range(4), help="Number of times to encode payloads (0-3, default 0)")
    parser.add_argument("-o", "--output", help="File to save scan results (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for query parameters and * detection")
    parser.add_argument("--require-star", action="store_true", help="Skip URLs without * in query parameters")
    args = parser.parse_args()

    display_welcome_message()

    payloads = load_payloads(args.payloads)
    print(f"\033[1;34m[i] Loaded {len(payloads)} payloads from {args.payloads}\033[0m")

    print("\n\033[1;33m[i] Loading, Please Wait...\033[0m")
    time.sleep(3)

    print("\033[1;34m[i] Starting BXSS vulnerability check\033[0m")
    print("\033[1;36m[i] Starting Web Driver, Please wait...\033[0m\n")

    start_time = time.time()
    vulnerable_urls = []

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
    except Exception as e:
        print(f"\033[0;31m[!] Failed to initialize WebDriver: {e}\033[0m")
        if args.debug:
            print(f"\033[0;33m[DEBUG] Exception details: {traceback.format_exc()}\033[0m")
        sys.exit(1)

    if args.url:
        valid_urls = scan_single_url(args.url, driver, args.encode, vulnerable_urls, payloads, args.debug, args.require_star)
    elif args.file:
        valid_urls = scan_urls_from_file(args.file, driver, args.encode, vulnerable_urls, payloads, args.debug, args.require_star)
    else:
        valid_urls = scan_urls_from_stdin(driver, args.encode, vulnerable_urls, payloads, args.debug, args.require_star)

    total_scanned = len(valid_urls)

    driver.quit()

    elapsed_time = time.time() - start_time
    print(f"\033[1;33m[i] Scan finished!\033[0m")
    print(f"\033[1;33m[i] Total URLs Scanned: {total_scanned}\033[0m")
    print(f"\033[1;33m[i] Time Taken: {int(elapsed_time)} seconds.\033[0m\n")

    save_results_to_file(vulnerable_urls, args.output)

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, handle_exit)
    main()