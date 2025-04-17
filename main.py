import argparse
import json
import logging
import os
import re
import sys
from typing import Dict, List, Optional

import boto3
import jsonschema
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class IAMPolicyAnalyzer:
    """
    A class to analyze AWS IAM policies for potential security vulnerabilities.
    """

    def __init__(self, policy_file: Optional[str] = None, policy_document: Optional[Dict] = None, policy_string: Optional[str] = None):
        """
        Initializes the IAMPolicyAnalyzer with a policy file or a policy document.
        """
        self.policy_document = None
        if policy_file:
            try:
                with open(policy_file, "r") as f:
                    self.policy_document = json.load(f)
            except FileNotFoundError:
                logging.error(f"Policy file not found: {policy_file}")
                raise
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON in policy file: {policy_file}")
                raise
        elif policy_document:
            self.policy_document = policy_document
        elif policy_string:
            try:
                self.policy_document = json.loads(policy_string)
            except json.JSONDecodeError:
                logging.error("Invalid JSON string provided")
                raise
        else:
            logging.error("No policy file or document provided.")
            raise ValueError("No policy file or document provided.")

    def analyze_policy(self) -> Dict:
        """
        Analyzes the IAM policy and identifies potential vulnerabilities.
        """
        results = {}
        results["overly_permissive"] = self.check_overly_permissive()
        results["wildcard_actions"] = self.check_wildcard_actions()
        results["unused_resources"] = self.check_unused_resources() #Placeholder. Needs implementation
        return results

    def check_overly_permissive(self) -> List[str]:
        """
        Checks for overly permissive permissions, such as "ec2:*".
        """
        overly_permissive = []
        if "Statement" in self.policy_document:
            for statement in self.policy_document["Statement"]:
                if "Action" in statement:
                    actions = (
                        statement["Action"]
                        if isinstance(statement["Action"], list)
                        else [statement["Action"]]
                    )
                    for action in actions:
                        if isinstance(action, str) and action.endswith(":*"):
                            overly_permissive.append(action)
        return overly_permissive

    def check_wildcard_actions(self) -> List[str]:
        """
        Checks for wildcard actions, such as "s3:Get*".
        """
        wildcard_actions = []
        if "Statement" in self.policy_document:
            for statement in self.policy_document["Statement"]:
                if "Action" in statement:
                    actions = (
                        statement["Action"]
                        if isinstance(statement["Action"], list)
                        else [statement["Action"]]
                    )
                    for action in actions:
                        if isinstance(action, str) and "*" in action:
                            wildcard_actions.append(action)
        return wildcard_actions

    def check_unused_resources(self) -> List[str]:
        """
        Placeholder for checking unused resources.  This functionality would
        require deeper analysis and potentially access to AWS account information.
        """
        #TODO: Implement logic to check for unused resources. Requires significant
        #additional implementation and potentially API access.
        return []


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Analyze AWS IAM policies for potential security vulnerabilities."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f",
        "--file",
        dest="policy_file",
        help="Path to the IAM policy JSON file.",
    )
    group.add_argument(
        "-j",
        "--json",
        dest="policy_string",
        help="IAM policy JSON string.",
    )
    return parser


def main() -> None:
    """
    Main function to parse arguments, analyze the policy, and print the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        if args.policy_file:
            analyzer = IAMPolicyAnalyzer(policy_file=args.policy_file)
        elif args.policy_string:
            analyzer = IAMPolicyAnalyzer(policy_string=args.policy_string)
        else:
            logging.error("No policy source specified.")
            sys.exit(1)


        results = analyzer.analyze_policy()

        print(json.dumps(results, indent=4))

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()