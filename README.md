[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-38a047.svg)](https://owasp.org/projects/)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/1390/badge)](https://bestpractices.coreinfrastructure.org/projects/1390)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

| Branch | Status |
|---|---|
| main | ![GHA build main](https://github.com/coreruleset/coreruleset/actions/workflows/test.yml/badge.svg?branch=main) |


# OWASP CRS

The OWASP Core Rule Set (CRS) is a set of generic attack detection rules for use with ModSecurity or compatible web application firewalls. CRS provides the baseline rule engine, anomaly scoring model, paranoia-level configuration, and production-oriented rule structure used in this thesis as the reference WAF platform.

# Context-Aware Generalized Rules for XSS and SQL Injection

This fork is maintained for the thesis project "Optimizing ModSecurity WAF Rules for Detecting XSS and SQL Injection Using Generalized Rules". The project focuses on improving rule-based detection for two high-impact web attack classes: Cross-Site Scripting (XSS) and SQL Injection (SQLi).

The core contribution is a Context-Aware Generalized Rules (CGR) rule set. Instead of relying on narrow enumeration of known payload strings, the CGR rules combine attack keywords with execution context, SQL semantics, encoding-aware normalization, and anomaly scoring. This design aims to increase detection coverage for encoded and obfuscated payloads while keeping false positives under control.

The thesis evaluates three rule configurations:

- baseline OWASP CRS;
- the referenced research-rule implementation (RR);
- the proposed CGR rule set.

The evaluation workflow uses Docker-based ModSecurity/CRS environments, GoTestWAF-driven benchmark execution, public XSS/SQLi datasets, benign traffic datasets, and audit-log analysis. The analysis process measures TP, FP, TN, FN, Recall, Precision, F1-score, and FPR, then uses ModSecurity audit logs to identify rules that should be tightened, rescored, or excluded.

The actively developed generalized rules are located in `rule_dev_v2/rules/` and mirrored into the benchmark environments when running experiments.

## Quick Start for This Fork

This repository currently focuses on three areas:

- `benchmark/test_environment/docker-compose.yml`: test environment for comparing CRS, RR, and CGR.
- `rule_dev_v2/rules/`: CGR rules under active development.

Minimum requirements:

- Docker + Docker Compose plugin.
- `curl`.

### Run the Test Environment

Start the environment with Docker Compose:

```bash
git clone https://github.com/quanlh30504/coreruleset-with-custom-rules.git
cd coreruleset-with-custom-rules
docker compose -f benchmark/test_environment/docker-compose.yml up -d
docker compose -f benchmark/test_environment/docker-compose.yml ps
```

Endpoints:

| Rule set | URL |
|---|---|
| Original CRS | `http://localhost:8090` |
| CRS + RR | `http://localhost:8091` |
| CRS + CGR v2 | `http://localhost:8092` |

Quick smoke test:

```bash
curl -s -o /dev/null -w "CRS=%{http_code}\n" "http://localhost:8090/?q=<script>alert(1)</script>"
curl -s -o /dev/null -w "RR=%{http_code}\n"  "http://localhost:8091/?q=<script>alert(1)</script>"
curl -s -o /dev/null -w "CGR=%{http_code}\n" "http://localhost:8092/?q=<script>alert(1)</script>"
```

Run the benchmark:

```bash
bash benchmark/test_environment/scripts/run_rq1_tests.sh
```

Stop the environment:

```bash
docker compose -f benchmark/test_environment/docker-compose.yml down
```

### Apache Setup

Install Apache and ModSecurity:

```bash
sudo apt update
sudo apt install -y apache2 libapache2-mod-security2
sudo cp -n /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo a2enmod security2 proxy proxy_http headers
```

Copy CRS and CGR:

```bash
git clone https://github.com/quanlh30504/coreruleset-with-custom-rules.git
cd coreruleset-with-custom-rules
sudo mkdir -p /etc/crs4
sudo rsync -a --delete "$PWD"/ /etc/crs4/
sudo cp /etc/crs4/crs-setup.conf.example /etc/crs4/crs-setup.conf

sudo cp "$PWD"/rule_dev_v2/rules/REQUEST-941-XSS-GENERALIZED-v2.conf /etc/crs4/rules/
sudo cp "$PWD"/rule_dev_v2/rules/REQUEST-942-SQLI-GENERALIZED-v2.conf /etc/crs4/rules/
sudo cp "$PWD"/rule_dev_v2/rules/TUNING-EXCLUSIONS.conf /etc/crs4/rules/REQUEST-900-TUNING-EXCLUSIONS.conf
```

In `/etc/modsecurity/modsecurity.conf`, start in observation mode:

```apache
SecRuleEngine DetectionOnly
```

Create `/etc/apache2/conf-available/crs4.conf`:

```apache
<IfModule security2_module>
    IncludeOptional /etc/crs4/crs-setup.conf
    IncludeOptional /etc/crs4/plugins/*-config.conf
    IncludeOptional /etc/crs4/plugins/*-before.conf
    IncludeOptional /etc/crs4/rules/*.conf
    IncludeOptional /etc/crs4/plugins/*-after.conf
</IfModule>
```

Enable the config and reload Apache:

```bash
sudo a2enconf crs4
sudo apachectl configtest
sudo systemctl reload apache2
```

After validation is complete, switch to:

```apache
SecRuleEngine On
```

If Apache already includes the distro-provided CRS configuration, remove that default include to avoid loading duplicate rule IDs.

## CRS Resources

Please see the [OWASP CRS page](https://coreruleset.org/) to get introduced to CRS and view resources on installation, configuration, and working with CRS.

## Contributing to CRS

We strive to make the OWASP CRS accessible to a wide audience of beginner and experienced users. We are interested in hearing any bug reports, false-positive alert reports, evasions, usability issues, and suggestions for new detections.

[Create an issue on GitHub](https://github.com/coreruleset/coreruleset/issues) to report a false positive or false negative (evasion). Please include your installed version and the relevant portions of your audit log. We will try and address your issue and potentially ask for additional information to reproduce your problem. Please also note that stale issues will be flagged and closed after 120 days. You can search for stale issues with the following [search query](https://github.com/coreruleset/coreruleset/issues?q=label%3A%22Stale+issue%22).

[Sign up for our Google Group](https://groups.google.com/a/owasp.org/g/modsecurity-core-rule-set-project) to ask general usage questions and participate in discussions on the CRS. Also [here](https://lists.owasp.org/pipermail/owasp-modsecurity-core-rule-set/index) you can find the archives for the previous mailing list.

[Join the #coreruleset channel on OWASP Slack](https://owasp.slack.com/) to chat about the CRS. ([Click here](https://owasp.org/slack/invite) to get an invitation if you are not yet registered on the OWASP slack. It's open to non-members too.)

Read also our documentation on [how to contribute](./CONTRIBUTING.md).

## License

Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.</br>
Copyright (c) 2021-2025 CRS project. All rights reserved.

The OWASP CRS is distributed under Apache Software License (ASL) version 2. Please see the enclosed LICENSE file for full details.
