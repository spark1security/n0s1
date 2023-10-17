#!/usr/bin/env python3

import json
import logging
import os
import sys


class GitlabDASTReport:
    def __init__(self, n0s1_data=None):
        tool_name = n0s1_data.get("tool", {}).get("name", "")
        tool_version = n0s1_data.get("tool", {}).get("version", "")
        prvd = n0s1_data.get("tool", {}).get("author", "")
        self.vulns: list[dict] = []
        self.report = {
            "version": "14.1.2",
            "vulnerabilities": self.vulns,
            "scan": {
                "start_time": "2000-01-01T00:00:00",
                "end_time": "2000-01-01T00:30:00",
                "status": "success",
                "type": "dast",
                "scanner": {
                    "id": tool_name,
                    "name": f"{tool_name} secret scanner by {prvd} - version: [{tool_version}]",
                    "url": "https://spark1.us/n0s1",
                    "version": tool_version,
                    "vendor": {
                        "name": prvd,
                    },
                },
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

                finding_message = f"Potential Secret Leak on {platform} {field}"
                solution = f"\nPlease verify the {platform} ticket and conduct a thorough search for any sensitive data. If a data leak is confirmed, proceed to rotate the data and eliminate any sensitive information from the ticket. Ticket URL: {url}"

                message = finding_message
                message += f"\nDetails:\nSensitive data type: [{match_id}] - Description: [{match_description}]\nPlatform: [{platform}] - Field: [ticket {field}]\nSource: {url}"
                message += f"\n000000000000000 Sensitive data found (redacted) 000000000000000\n{secret}\n000000000000000 Sensitive data found (redacted) 000000000000000"
                finding_description = message.replace("<REDACTED>", "xxxxxxxxxxxx")

                severity = "Info"
                identifiers_name = match_description
                identifiers_value = match_id

                self.vulns.append(
                    {
                        "id": finding_instance_id,
                        "category": "dast",
                        "name": finding_message,
                        "cve": "",
                        "description": finding_description,
                        "solution": solution,
                        "evidence": {
                            "source": {
                                "id": "assert:Intel",
                                "name": "n0s1 regex match"
                            },
                            "summary": (
                                f"Evidence is supplied in form of n0s1 regex "
                                "match in the response output below."
                            ),
                            "request": {
                                "headers": [],
                                "method": "Procedure",
                                "body": "",
                                "url": url
                            },
                            "response": {
                                "headers": [],
                                "reason_phrase": "OK",
                                "status_code": 200,
                                "body": secret,
                            },
                        },
                        "severity": severity,
                        "confidence": "low",
                        "scanner": {
                            "id": "n0s1",
                            "name": "n0s1",
                        },
                        "identifiers": [
                            {
                                "type": "n0s1",
                                "name": identifiers_name,
                                "url": "https://spark1.us/n0s1",
                                "value": identifiers_value
                            }
                        ],
                        "links": [url],
                        "location": {
                            "hostname": url,
                            "method": "",
                            "param": "",
                            "path": "",
                        }
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