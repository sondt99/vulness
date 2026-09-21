"""Command line entry point. Exists so cache_report has a real caller."""
import sys

from client.sync import cache_report, fetch_report


def main():
    report_id, org, name = sys.argv[1], sys.argv[2], sys.argv[3]
    body = fetch_report(report_id, org)
    print(cache_report(name, str(body)))


if __name__ == "__main__":
    main()
