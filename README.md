# n0s1 - Secret Scanner
n0s1 ([pronunciation](https://en.wiktionary.org/wiki/nosy#Pronunciation)) is an open-source secret scanner designed for Project Management and Issue Tracker tools such as Jira, Confluence and Linear.app. It scans all tickets/items/issues within the chosen platform in search of any leaked secrets in the titles, bodies, and comments.

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
* [Confluence](https://www.atlassian.com/software/confluence)
* [Linear](https://linear.app/)

### Quick Start
[CLI:](https://pypi.org/project/n0s1/)
```bash
python3 -m pip install n0s1
n0s1 jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
```

[Docker:](https://hub.docker.com/r/spark1security/n0s1)
```bash
docker run spark1security/n0s1 jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
```

[From source:](https://github.com/spark1security/n0s1#quick-start)
```bash
git clone https://github.com/spark1security/n0s1.git
cd n0s1/src/n0s1
python3 -m venv n0s1_python
source n0s1_python/bin/activate
python3 -m pip install -r ../../requirements.txt
python3 n0s1.py jira_scan --server "https://<YOUR_JIRA_SERVER>.atlassian.net" --api-key "<YOUR_JIRA_API_TOKEN>"
deactivate
```

[GitHub Actions:](https://github.com/marketplace/actions/spark-1-n0s1)
```yaml
jobs:
  jira_secret_scanning:
    steps:
      - uses: spark1security/n0s1-action@main
        env:
          JIRA_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
        with:
          scan-target: 'jira_scan'
          user-email: 'service_account@<YOUR_COMPANY>.atlassian.net'
          platform-url: 'https://<YOUR_COMPANY>.atlassian.net'
```

GitLab CI - Add the following job to your .gitlab-ci.yml file:
```yaml
jira-scan:
  stage: dast
  image:
    name: spark1security/n0s1
    entrypoint: [""]
  script:
    - n0s1 jira_scan --email "service_account@<YOUR_COMPANY>.atlassian.net" --api-key $JIRA_TOKEN --server "https://<YOUR_COMPANY>.atlassian.net" --report-file gl-dast-report.json --report-format gitlab
    - apt-get update
    - apt-get -y install jq
    - cat gl-dast-report.json | jq
  artifacts:
    reports:
      dast:
        - gl-dast-report.json
```

## Want more? Check out Spark 1

If you liked n0s1, you will love Spark 1 which builds on top of n0s1 to provide even more enhanced capabilities for a complete security management offering.

Don't forget to check out the <https://spark1.us> website for more information about our products and services.

If you'd like to contact Spark 1 or request a demo, please use the [free consultation form](https://spark1.us/contact-us-1).

## Community

n0s1 is a [Spark 1](https://spark1.us) open source project.  
Learn about our open source work and portfolio [here](https://spark1.us/n0s1).  
Contact us about any matter by opening a GitHub Discussion [here](https://github.com/spark1security/n0s1/issues)
