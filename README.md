# n0s1 - Secret Scanner
n0s1 (pronounced as nosy, /ˈnōzē/) is an open source secret scanner for Project Management and Issue Tracker tools.

The scanner will traverse all items within the target platform (e.g. Jira or Linear) and find leaked secrets in the ticket's title, body and comments.

The secrets are matched based on an extensible configuration file (regex.toml). The scanner looks for sensitive data such as:
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
```bash
cd src/n0s1
python3 -m pip install n0s1
n0s1 jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
```
From source:
```bash
cd src/n0s1
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
