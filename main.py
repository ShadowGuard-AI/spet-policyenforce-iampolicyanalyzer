import argparse
import json
import logging
import sys
from typing import Dict, List, Optional


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
        # Source priority is silent: file beats document beats string when
        # several are supplied, and nothing tells the caller which source
        # was actually analyzed.
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

    def statements(self):
        """Normalize Statement to a list; a single statement object becomes a one item list."""
        if not isinstance(self.policy_document, dict):
            return []
        stmt = self.policy_document.get("Statement")
        if stmt is None:
            return []
        if isinstance(stmt, dict):
            return [stmt]
        if isinstance(stmt, list):
            for i, entry in enumerate(stmt):
                if not isinstance(entry, dict):
                    raise ValueError(f"Statement entry {i} is not an object.")
            return list(stmt)
        raise ValueError("Statement must be an object or a list of objects.")

    def analyze_policy(self) -> Dict:
        if not self.statements():
            raise ValueError("Policy has no statements to analyze.")
        for i, statement in enumerate(self.statements()):
            if self._effect(statement) not in ("allow", "deny"):
                raise ValueError(f"Statement {i} has a missing or invalid Effect: {statement.get('Effect')!r}.")
        results = {}
        results["overly_permissive"] = self.check_overly_permissive()
        results["wildcard_actions"] = self.check_wildcard_actions()
        results["wildcard_resources"] = self.check_wildcard_resources()
        return results

    @staticmethod
    def _effect(statement):
        return str(statement.get("Effect", "")).strip().lower()

    def _allow_statements(self):
        # Effect is normalized (case and surrounding whitespace) and was
        # validated by analyze_policy, so only a real Allow reaches here.
        return [s for s in self.statements() if self._effect(s) == "allow"]

    def _values(self, statement, key):
        v = statement.get(key)
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    def check_overly_permissive(self) -> List[str]:
        findings = []
        for statement in self._allow_statements():
            for action in self._values(statement, "Action"):
                # No dedupe happens in these lists. The same action granted by three
                # statements is reported three times, and an action ending in colon
                # star lands here and again in wildcard_actions, so the buckets
                # overlap by design and cannot be summed.
                if isinstance(action, str) and (action == "*" or action.endswith(":*")):
                    findings.append(action)
            for na in self._values(statement, "NotAction"):
                if isinstance(na, str):
                    findings.append(f"NotAction: {na}")
            resources = self._values(statement, "Resource")
            actions = self._values(statement, "Action")
            if any(r == "*" for r in resources) and actions:
                for a in actions:
                    label = f"{a} on *"
                    if label not in findings:
                        findings.append(label)
        return findings

    def check_wildcard_actions(self) -> List[str]:
        findings = []
        for statement in self._allow_statements():
            for action in self._values(statement, "Action"):
                if isinstance(action, str) and "*" in action:
                    findings.append(action)
        return findings

    def check_wildcard_resources(self) -> List[str]:
        findings = []
        for statement in self._allow_statements():
            # A star anywhere in the resource string flags it, so a scoped ARN
            # with one wildcard segment is listed beside a bare star that opens
            # everything. The report keeps the string itself, which is the only
            # way to tell those two apart.
            for resource in self._values(statement, "Resource"):
                if isinstance(resource, str) and "*" in resource:
                    findings.append(resource)
        return findings


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