#!/usr/bin/env python3

import json
import logging
import os
import sys


def _n0s1_rule_2_sarif_rule(n0s1_data):
    sarif_rules = []
    n0s1_rules = n0s1_data.get("regex_config", {}).get("rules", [])
    for r in n0s1_rules:
        id = r.get("id", "")
        description = r.get("description", "")
        sarif_r = {
            "id": id,
            "name": description,
            "shortDescription": {
                "text": description
            },
            "fullDescription": {
                "text": f"{description}"
            },
            "defaultConfiguration": {
                "level": "note"
            },
            "helpUri": "https://spark1.us/n0s1"
        }
        sarif_rules.append(sarif_r)
    return sarif_rules


class SarifReport:
    def __init__(self, n0s1_data) -> None:
        tool_name = n0s1_data.get("tool", {}).get("name", "")
        tool_version = n0s1_data.get("tool", {}).get("version", "")
        prvd = n0s1_data.get("tool", {}).get("author", "")
        self.results: list[dict] = []
        self.rules: list[dict] = []
        self.seen_rules: set[str] = set()
        self.rules = _n0s1_rule_2_sarif_rule(n0s1_data)

        for rule in self.rules:
            self.seen_rules.add(rule["id"])

        self.report = {
            "version": "2.1.0",
            "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.4",
            "runs": [
                {
                    "tool": {"driver": {"name": tool_name, "rules": self.rules, "version": tool_version,
                                        "fullName": f"{tool_name} secret scanner by {prvd} - version: [{tool_version}]",
                                        "informationUri": "https://github.com/spark1security/n0s1"}
                             },
                    "results": self.results,
                }
            ],
        }
        if n0s1_data:
            self.add_vulns(n0s1_data)

    def get_rule_index(self, rule_id):
        index = 0
        for r in self.rules:
            index += 1
            if rule_id.lower() == r.get("id", "").lower():
                return index
        return -1

    def add_vulns(self, n0s1_data: dict):
        findings = n0s1_data.get("findings", [])
        for key in findings:
            d = findings[key]
            try:
                url = d.get("url", "")
                secret = d.get("secret", "")
                platform = d.get("details", {}).get("platform", "PM software")
                field = d.get("details", {}).get("ticket_field", "ticket")
                level = "note"
                match = d.get("details", {}).get("matched_regex_config", {})
                match_id = match.get("id", "")
                ruleId = match_id
                match_description = match.get("description", "")
                ruleIndex = self.get_rule_index(ruleId)
                finding_id = d.get("id", "None")

                if ruleId not in self.seen_rules:
                    self.rules.append(
                        {
                            "id": ruleId,
                            "name": f"Secret Leak - {ruleId}",
                            "shortDescription": {"text": ruleId},
                            "fullDescription": {"text": ruleId},
                            "defaultConfiguration": {"level": "note"},
                            "helpUri": "https://spark1.us/n0s1"
                        }
                    )

                message = f"Potential Secret Leak on [{platform}]({url})."
                message += f"\nDetails:\nSensitive data type: [{match_id}] - Description: [{match_description}]\nPlatform: [{platform}] - Field: [ticket {field}]\nSource: {url}"
                message += f"\n000000000000000 Sensitive data found (redacted) 000000000000000\n{secret}\n000000000000000 Sensitive data found (redacted) 000000000000000"
                message += f"\nPlease verify the [{platform} ticket]({url}) and conduct a thorough search for any sensitive data. If a data leak is confirmed, proceed to rotate the data and eliminate any sensitive information from the ticket."
                message = message.replace("<REDACTED>", "xxxxxxxxxxxx")

                self.results.append(
                    {
                        "ruleId": ruleId,
                        "ruleIndex": ruleIndex,
                        "message": {"text": message},
                        "level": level,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding_id, "uriBaseId": "ROOTPATH"},
                                    "region": {
                                        "startLine": 1,
                                        "startColumn": 1,
                                        "endLine": 1,
                                        "endColumn": 1
                                    }
                                },
                                "message": {
                                    "text": url
                                }
                            }
                        ]
                    }
                )
            except KeyError:
                logging.info("Warning! Unexpected JSON format")
                pass
            except Exception as e:
                logging.info(str(e))

    def write_report(self, file="report.sarif") -> None:
        existing_sarif_data = None
        if os.path.exists(file):
            with open(file) as f:
                existing_sarif_data = json.load(f)

        result = None
        if existing_sarif_data and "runs" in existing_sarif_data and "runs" in self.report:
            result = existing_sarif_data
            result["runs"] += self.report["runs"]
        else:
            result = self.report

        with open(file, "w") as f:
            f.write(json.dumps(result))
            logging.info(f"Secret scanner report saved to: [{file}].")


def n0s1_report_to_sarif_report(n0s1_report):
    return SarifReport(n0s1_report)


def n0s1_report_file_to_sarif_report_file(input_report_path, output_report_path):
    if os.path.exists(input_report_path):
        with open(input_report_path) as f:
            data = json.load(f)
            logging.info(f"Parsing report file [{input_report_path}]...")
            sarif_report = n0s1_report_to_sarif_report(data)
            if len(sarif_report.results) <= 0:
                logging.info(f"No leaks found on file: [{input_report_path}].")
            sarif_report.write_report(output_report_path)
    else:
        logging.info(f"Skipping report file: [{input_report_path}]")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)

    INPUT_REPORT_PATH = "n0s1_report.json"
    OUTPUT_REPORT_PATH = "n0s1_report.sarif"

    if len(sys.argv) > 1:
        INPUT_REPORT_PATH = sys.argv[1]
    if len(sys.argv) > 2:
        OUTPUT_REPORT_PATH = sys.argv[2]

    n0s1_report_file_to_sarif_report_file(INPUT_REPORT_PATH, OUTPUT_REPORT_PATH)