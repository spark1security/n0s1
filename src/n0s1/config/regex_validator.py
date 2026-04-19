import re
import yaml
import sys


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_rules(data):
    errors = []

    for rule in data.get("rules", []):
        rule_id = rule.get("id")
        regex = rule.get("regex")
        example = rule.get("example")

        if not regex or not example:
            errors.append(f"[{rule_id}] Missing regex or example")
            continue

        try:
            pattern = re.compile(regex)
        except re.error as e:
            errors.append(f"[{rule_id}] Invalid regex: {e}")
            continue

        if not pattern.search(example):
            errors.append(
                f"[{rule_id}] Example does NOT match regex\n"
                f"  Regex: {regex}\n"
                f"  Example: {example}"
            )
        else:
            print(f"[OK] {rule_id}")

    return errors


def main():

    if len(sys.argv) < 2:
        path ="regex.yaml"
    else:
        path = sys.argv[1]

    data = load_yaml(path)
    total_rules = len(data.get("rules", []))

    errors = test_rules(data)

    if errors:
        message = f"\n❌ Total of [{len(errors)}]/[{total_rules}] errors found!\n"
        print(message)
        for err in errors:
            print(err)
            print("-" * 60)
        print(message)
        sys.exit(1)
    else:
        print("\n✅ All regex examples matched successfully!")


if __name__ == "__main__":
    main()