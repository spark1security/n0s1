# n0s1 - Secret Scanner
n0s1 ([pronunciation](https://en.wiktionary.org/wiki/nosy#Pronunciation)) is an open-source secret scanner designed for Project Management and Issue Tracker tools such as Jira and Linear.app. It scans all tickets/items/issues within the chosen platform in search of any leaked secrets in the titles, bodies, and comments.

These secrets are identified by comparing them against an adaptable configuration file named [regex.toml](https://github.com/spark1security/n0s1/blob/main/src/n0s1/config/regex.toml). The scanner specifically looks for sensitive information, which includes:
* Github Personal Access Tokens
* GitLab Personal Access Tokens
* AWS Access Tokens
* PKCS8 private keys
* RSA private keys
* SSH private keys
* npm access tokens

### Currently supported target platforms:
* [Jira](https://www.atlassian.com/software/jira)
* [Linear](https://linear.app/)

### Usage
CLI:
```bash
python3 -m pip install n0s1
n0s1 jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
```

Docker:
```bash
docker run spark1security/n0s1 jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
```

From source:
```bash
git clone https://github.com/spark1security/n0s1.git
cd n0s1/src/n0s1
python3 -m venv n0s1_python
source n0s1_python/bin/activate
python3 -m pip install -r ../../requirements.txt
python3 n0s1.py jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
deactivate
```

## Community

n0s1 is a [Spark 1](https://spark1.us) open source project.  
Learn about our open source work and portfolio [here](https://spark1.us/n0s1).  
Contact us about any matter by opening a GitHub Discussion [here](https://github.com/spark1security/n0s1/issues)
