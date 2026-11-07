# spet-policyenforce-IAMPolicyAnalyzer
A command-line utility to analyze AWS IAM policies held in local files or passed as a JSON string. It uses only the Python standard library; it does not call AWS, does not use boto3, and does not retrieve policy documents from anywhere.

Checks, over Allow statements only (Deny statements are never reported as permissive findings; the Effect value is matched ignoring letter case and surrounding whitespace):
- Overly permissive: an action that is the bare `*` or ends in `:*`, any action granted on resource `*` (reported as `<action> on *`), and any `NotAction` entry in an Allow statement (reported as `NotAction: <action>`, because an Allow with NotAction grants every other action).
- Wildcard actions: any action containing `*`.
- Wildcard resources: any resource containing `*`.

Every statement must carry an Effect of Allow or Deny: a statement with a missing or other Effect value is invalid input and the run exits non-zero, as does a Statement entry that is not an object or a Statement that is neither an object nor a list.

A `Statement` given as a single object is accepted and treated as a one item list. A policy with no statements is a not-performed run: the tool prints an error and exits non-zero instead of reporting clean lists. The tool makes no claim about unused roles or unused resources; no such check is performed and no such field is reported.

## Install
`git clone https://github.com/ShadowGuard-AI/spet-policyenforce-iampolicyanalyzer`

## Usage
`python3 main.py -f POLICY_FILE` or `python3 main.py -j 'POLICY_JSON_STRING'`

## Parameters
- `-h`: Show help message and exit
- `-f`, `--file`: Path to the IAM policy JSON file.
- `-j`, `--json`: IAM policy JSON string.

## License
MIT License. See LICENSE.
