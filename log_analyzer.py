#!/usr/bin/env python3
"""
log_analyzer.py - Simple log analysis tool for learning and DFIR practice

Features:
- Count occurrences of keywords
- Show top N IP addresses found in the log (regex-based)
- Show lines matching a regex (for quick IOC searches)
- Export summary to CSV
- Basic parsing of common timestamp patterns to show first/last event (best-effort)

Usage examples:
    python log_analyzer.py analyze --file example.log --top-ips 10
    python log_analyzer.py grep --file example.log --pattern "ERROR|Exception"
    python log_analyzer.py keywords --file example.log --words "error,failed,timeout"
    python log_analyzer.py export --file example.log --out summary.csv

Notes:
- This tool is educational. Use it on logs you own or have permission to analyze.
- Works best on plain-text logs (Apache, syslog, application logs).
"""

import argparse
import re
import csv
from collections import Counter
from datetime import datetime

IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
# timestamp regexes (very permissive, best-effort)
TIMESTAMP_PATTERNS = [
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',           # 2023-08-01T12:34:56
    r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',          # 2023-08-01 12:34:56
    r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}',              # Aug  1 12:34:56 (syslog)
]

def read_lines(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.rstrip('\n') for line in f]

def find_top_ips(lines, top_n=10):
    ips = IP_REGEX.findall("\n".join(lines))
    counts = Counter(ips)
    return counts.most_common(top_n)

def grep_lines(lines, pattern):
    rx = re.compile(pattern, re.IGNORECASE)
    return [line for line in lines if rx.search(line)]

def count_keywords(lines, keywords):
    kws = [k.lower() for k in keywords]
    counts = Counter()
    for line in lines:
        low = line.lower()
        for k in kws:
            if k in low:
                counts[k] += 1
    return counts

def find_timestamps(lines):
    ts = []
    for line in lines:
        for pat in TIMESTAMP_PATTERNS:
            match = re.search(pat, line)
            if match:
                ts.append(match.group(0))
                break
    return ts

def parse_args():
    p = argparse.ArgumentParser(description="Simple Log Analyzer (educational)")
    sp = p.add_subparsers(dest='cmd', required=True)

    p_an = sp.add_parser('analyze', help='Show summary: top IPs, timestamps overview, line count')
    p_an.add_argument('--file', '-f', required=True, help='Path to log file')
    p_an.add_argument('--top-ips', type=int, default=10, help='Number of top IPs to show')

    p_grep = sp.add_parser('grep', help='Show lines matching a regex pattern')
    p_grep.add_argument('--file', '-f', required=True, help='Path to log file')
    p_grep.add_argument('--pattern', '-p', required=True, help='Regex pattern')

    p_kw = sp.add_parser('keywords', help='Count occurrences of comma-separated keywords')
    p_kw.add_argument('--file', '-f', required=True, help='Path to log file')
    p_kw.add_argument('--words', '-w', required=True, help='Comma separated keywords (e.g. error,failed)')

    p_exp = sp.add_parser('export', help='Export a summary CSV with top IPs and keyword counts')
    p_exp.add_argument('--file', '-f', required=True, help='Path to log file')
    p_exp.add_argument('--out', '-o', required=True, help='Output CSV file path')
    p_exp.add_argument('--top-ips', type=int, default=10, help='Number of top IPs to include')

    return p.parse_args()

def analyze(file, top_ips=10):
    lines = read_lines(file)
    print(f"[+] Lines read: {len(lines)}")
    top = find_top_ips(lines, top_ips)
    if top:
        print(f"[+] Top {top_ips} IPs:")
        for ip, c in top:
            print(f"    {ip} — {c}")
    else:
        print("[+] No IPs found.")

    ts = find_timestamps(lines)
    if ts:
        print(f"[+] Sample timestamps found (first 5): {ts[:5]}")
    else:
        print("[+] No timestamps detected with default patterns.")

def export_summary(file, out, top_ips=10):
    lines = read_lines(file)
    top = find_top_ips(lines, top_ips)
    keywords = ['error','failed','exception','timeout','denied']
    kw_counts = count_keywords(lines, keywords)

    with open(out, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['metric','value'])
        writer.writerow(['lines', len(lines)])
        writer.writerow([])
        writer.writerow(['top_ips','count'])
        for ip, c in top:
            writer.writerow([ip, c])
        writer.writerow([])
        writer.writerow(['keyword','count'])
        for k, v in kw_counts.items():
            writer.writerow([k, v])

    print(f"[+] Summary exported to {out}")

def main():
    args = parse_args()
    if args.cmd == 'analyze':
        analyze(args.file, args.top_ips)
    elif args.cmd == 'grep':
        lines = read_lines(args.file)
        matches = grep_lines(lines, args.pattern)
        for m in matches:
            print(m)
        print(f"[+] Found {len(matches)} matching lines.")
    elif args.cmd == 'keywords':
        lines = read_lines(args.file)
        kws = [w.strip() for w in args.words.split(',') if w.strip()]
        counts = count_keywords(lines, kws)
        for k, v in counts.items():
            print(f"{k}: {v}")
    elif args.cmd == 'export':
        export_summary(args.file, args.out, args.top_ips)

if __name__ == '__main__':
    main()
