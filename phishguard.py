
import argparse
import os
from core.parser import parse_url
from core.scorer import score_url, pretty_print_report, to_json

def scan_url(url: str, json_out: bool=False):
    parsed = parse_url(url)
    report = score_url(parsed)
    if json_out:
        print(to_json(report))
    else:
        pretty_print_report(report)

def scan_file(file_path: str, json_out: bool=False):
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if url:
                scan_url(url, json_out=json_out)

def main():
    parser = argparse.ArgumentParser(description="PhishGuard - URL risk analyzer")
    parser.add_argument("command", choices=["scan"], help="Scan URLs for phishing indicators")
    parser.add_argument("target", help="A URL or a path to a file containing URLs")
    parser.add_argument("--json", action="store_true", help="Output machine readable JSON")
    args = parser.parse_args()

    if args.command == "scan":
        if os.path.isfile(args.target):
            scan_file(args.target, json_out=args.json)
        else:
            scan_url(args.target, json_out=args.json)

if __name__ == "__main__":
    main()
