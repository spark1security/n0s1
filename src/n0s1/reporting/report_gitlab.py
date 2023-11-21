#!/usr/bin/env python3

import json
import logging
import os
import sys
from datetime import datetime, timezone


class GitlabDASTReport:
    def __init__(self, n0s1_data=None):
        datetime_now_obj = datetime.now(timezone.utc)
        date_now = datetime_now_obj.strftime("%Y-%m-%dT%H:%M:%S")
        start_date = n0s1_data.get("scan_date", {}).get("date_utc", "")
        tool_name = n0s1_data.get("tool", {}).get("name", "")
        tool_version = n0s1_data.get("tool", {}).get("version", "")
        prvd = n0s1_data.get("tool", {}).get("author", "")
        scan_target = n0s1_data.get("tool", {}).get("scan_arguments", {}).get("scan_target", "")
        label = n0s1_data.get("tool", {}).get("scan_arguments", {}).get("label", "")
        contact_help = n0s1_data.get("tool", {}).get("scan_arguments", {}).get("contact_help", "")
        report_format = n0s1_data.get("tool", {}).get("scan_arguments", {}).get("report_format", "")
        self.vulns: list[dict] = []
        self.report = {
            "version": "15.0.6",
            "vulnerabilities": self.vulns,
            "remediations": [],
            "scan": {
                "analyzer": {
                    "id": tool_name,
                    "name": f"{tool_name} secret scanner by {prvd} - version: [{tool_version}]",
                    "vendor": {"name": prvd},
                    "version": tool_version
                },
                "end_time": date_now,
                "messages": [],
                "options": [
                    {
                        "name": "scan_target",
                        "value": scan_target
                    },
                    {
                        "name": "label",
                        "value": label
                    },
                    {
                        "name": "contact_help",
                        "value": contact_help
                    },
                    {
                        "name": "report_format",
                        "value": report_format
                    }
                ],
                "scanned_resources": [],
                "scanner": {
                    "id": tool_name,
                    "name": f"{tool_name} secret scanner by {prvd} - version: [{tool_version}]",
                    "url": "https://spark1.us/n0s1",
                    "version": tool_version,
                    "vendor": {
                        "name": prvd,
                    },
                },
                "start_time": start_date,
                "status": "success",
                "type": "dast",
            },
        }
        if n0s1_data:
            self.add_vulns(n0s1_data)

    def add_vulns(self, n0s1_data: dict):
        findings = n0s1_data.get("findings", [])
        for key in findings:
            d = findings[key]
            try:
                finding_instance_id = d.get("id", "")
                url = d.get("url", "")
                secret = d.get("secret", "")
                platform = d.get("details", {}).get("platform", "PM software")
                field = d.get("details", {}).get("ticket_field", "ticket")
                match = d.get("details", {}).get("matched_regex_config", {})
                match_id = match.get("id", "")
                match_description = match.get("description", "")

                secret = secret.replace("<REDACTED>", "xxxxxxxxxxxx")

                finding_message = f"Potential Secret Leak on {platform} {field}."
                solution = f"\nPlease verify the {platform} ticket and conduct a thorough search for any sensitive data. If a data leak is confirmed, proceed to rotate the data and eliminate any sensitive information from the ticket. Ticket URL: {url}"

                message = finding_message
                message += f"\nSensitive data type: [{match_id}] - Sensitive data description: [{match_description}] - Platform: [{platform}] - Field: [ticket {field}] - Source: {url}"
                finding_description = message

                severity = "Info"
                identifiers_name = match_description
                identifiers_value = match_id

                self.vulns.append(
                    {
                        "id": finding_instance_id,
                        "description": finding_description,
                        "details": {
                            "discovered_at": {
                                "name": "Discovered at:",
                                "type": "text",
                                "value": f"{field} field on {platform}"
                            },
                            "sanitized_secret": {
                                "name": "Sensitive data found (redacted):",
                                "type": "text",
                                "value": f"[{secret}]"
                            },
                            "urls": {
                                "items": [{"href": url, "type": "url"}],
                                "name": "URLs",
                                "type": "list"
                            }
                        },
                        "evidence": {
                            "summary": (
                                f"Potential leaked secret (sanitized): [{secret}]"
                            ),
                            "request": {
                                "headers": [],
                                "method": "GET",
                                "url": url
                            },
                            "response": {
                                "headers": [],
                                "reason_phrase": "OK",
                                "status_code": 200,
                            },
                        },
                        "identifiers": [
                            {
                                "type": "regex",
                                "name": identifiers_name,
                                "url": "https://github.com/spark1security/n0s1/blob/main/src/n0s1/config/regex.yaml",
                                "value": identifiers_value
                            }
                        ],
                        "links": [
                            {"name": f"{platform} {field}", "url": url},
                            {"name": "Documentation - n0s1 Secret Scanner", "url": "https://spark1.us/n0s1"},
                        ],
                        "location": {
                            "hostname": url,
                            "method": "",
                            "param": "",
                            "path": "",
                        },
                        "name": finding_message,
                        "severity": severity,
                        "solution": solution
                    }
                )
            except KeyError:
                logging.info("Warning! Unexpected JSON format")
                pass
            except Exception as e:
                logging.info(str(e))

    def write_report(self, file="gl-dast-report.json") -> None:
        with open(file, "w") as f:
            f.write(json.dumps(self.report))


def n0s1_report_to_gitlab_report(n0s1_report):
    return GitlabDASTReport(n0s1_report)


def n0s1_report_file_to_gitlab_report_file(input_report_path, output_report_path):
    if os.path.exists(input_report_path):
        with open(input_report_path) as f:
            data = json.load(f)
            logging.info(f"Parsing report file [{output_report_path}]...")
            gitlab_report = GitlabDASTReport(data)
            if len(gitlab_report.vulns) <= 0:
                logging.info(f"No leaks found on file: [{output_report_path}].")
            gitlab_report.write_gitlab_report(output_report_path)
    else:
        logging.info(f"Skipping report file: [{output_report_path}]")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)

    INPUT_REPORT_PATH = "n0s1_report.json"
    OUTPUT_REPORT_PATH = "gl-dast-report.json"

    if len(sys.argv) > 1:
        INPUT_REPORT_PATH = sys.argv[1]
    if len(sys.argv) > 2:
        OUTPUT_REPORT_PATH = sys.argv[2]

    n0s1_report_file_to_gitlab_report_file(INPUT_REPORT_PATH, OUTPUT_REPORT_PATH)