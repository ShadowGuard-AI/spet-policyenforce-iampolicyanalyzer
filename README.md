# spet-policyenforce-IAMPolicyAnalyzer
A command-line utility to analyze AWS IAM policies. It takes an IAM policy JSON file as input and identifies potential security vulnerabilities, such as overly permissive permissions or unused roles. Relies on 'boto3' to retrieve policy document, and regex to parse and analyze policy. - Focused on Enforces security policies defined in YAML or JSON format. Can be used to validate configurations, scan infrastructure-as-code (IaC) templates, or enforce coding standards. Ensures consistent security practices across an organization.

## Install
`git clone https://github.com/ShadowStrikeHQ/spet-policyenforce-iampolicyanalyzer`

## Usage
`./spet-policyenforce-iampolicyanalyzer [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowStrikeHQ
