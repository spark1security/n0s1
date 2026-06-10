"""Verify that each regex rule's example is detected by the local scanner."""
import os
import sys
import time
import unittest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from n0s1.scanner import SecretScanner

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REGEX_YAML = os.path.join(REPO_ROOT, "src", "n0s1", "config", "regex.yaml")
TEST_FILE = "/tmp/n0s1_regex_test.txt"


class TestRegexExamples(unittest.TestCase):

    def setUp(self):
        self.data = {}
        with open(REGEX_YAML) as f:
            self.data = yaml.safe_load(f)

        self.examples = [
            rule["example"]
            for rule in self.data.get("rules", [])
            if rule.get("example")
        ]

    def test_leaked_secret_found_in_examples_file(self):

        for rule in self.data.get("rules", []):
            with open(TEST_FILE, "w") as f:
                example = rule.get("example", "EMPTY")
                f.write(example)
                time.sleep(0.2)

            scanner = SecretScanner(
                target="local_scan",
                scan_path=TEST_FILE,
                regex_file=REGEX_YAML,
                private=True,
            )
            scanner.scan()

            findings = scanner.get_report().get("findings", {})
            self.assertGreater(len(findings), 0, f"Secret type: [{rule.get("id", "EMPTY")}] - Expected secret:[{example}] to match regex:[{rule.get("regex", "")}].")


if __name__ == "__main__":
    unittest.main()
