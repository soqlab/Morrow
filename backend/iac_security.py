from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List


_RESOURCE_RE = re.compile(r'resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{', re.IGNORECASE)


def _matching_blocks(content: str, resource_type: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for match in _RESOURCE_RE.finditer(content or ""):
        if match.group("type") != resource_type:
            continue
        start = match.end()
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        out.append({"type": resource_type, "name": match.group("name"), "body": content[start : max(start, i - 1)]})
    return out


def _cidr_is_public(cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(str(cidr).strip().strip('"'), strict=False)
        return not (network.is_private or network.is_loopback or network.is_link_local)
    except Exception:
        return False


def evaluate_iac_security_content(content: str, file_path: str = "") -> Dict[str, Any]:
    """Small horizontal IaC-security prototype for Terraform content."""
    findings: List[Dict[str, Any]] = []
    text = str(content or "")

    for block in _matching_blocks(text, "aws_s3_bucket_public_access_block"):
        body = block["body"]
        bools = {
            key: bool(re.search(rf"\b{key}\s*=\s*true\b", body, re.IGNORECASE))
            for key in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            )
        }
        missing = [key for key, ok in bools.items() if not ok]
        if missing:
            findings.append(
                {
                    "rule_id": "IAC_AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                    "severity": "high",
                    "title": "S3 public access block is incomplete",
                    "resource": f"aws_s3_bucket_public_access_block.{block['name']}",
                    "file_path": file_path,
                    "evidence": {"missing_true_settings": missing},
                    "remediation": "Set all S3 public access block controls to true.",
                }
            )

    for block in _matching_blocks(text, "aws_security_group_rule") + _matching_blocks(text, "aws_vpc_security_group_ingress_rule"):
        body = block["body"]
        is_ingress = bool(re.search(r'\btype\s*=\s*"ingress"', body, re.IGNORECASE)) or block["type"] == "aws_vpc_security_group_ingress_rule"
        has_ssh = bool(re.search(r"\bfrom_port\s*=\s*22\b", body) or re.search(r"\bto_port\s*=\s*22\b", body))
        cidrs = re.findall(r'"([0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2})"', body)
        public_cidrs = [cidr for cidr in cidrs if _cidr_is_public(cidr)]
        if is_ingress and has_ssh and public_cidrs:
            findings.append(
                {
                    "rule_id": "IAC_OPEN_SSH_TO_INTERNET",
                    "severity": "critical",
                    "title": "SSH is open to a public CIDR",
                    "resource": f"{block['type']}.{block['name']}",
                    "file_path": file_path,
                    "evidence": {"public_cidrs": public_cidrs},
                    "remediation": "Restrict SSH ingress to an approved private or bastion CIDR.",
                }
            )

    iam_policy_blocks = (
        _matching_blocks(text, "aws_iam_policy")
        + _matching_blocks(text, "aws_iam_role_policy")
        + _matching_blocks(text, "aws_iam_user_policy")
        + _matching_blocks(text, "aws_iam_group_policy")
    )
    for block in iam_policy_blocks:
        body = block["body"]
        has_allow = bool(re.search(r'"?Effect"?\s*[:=]\s*"?Allow"?', body, re.IGNORECASE))
        has_admin_action = bool(re.search(r'"?Action"?\s*[:=]\s*(\[\s*)?"(\*|iam:\*)"', body, re.IGNORECASE))
        has_wild_resource = bool(re.search(r'"?Resource"?\s*[:=]\s*(\[\s*)?"\*"', body, re.IGNORECASE))
        if has_allow and has_admin_action and has_wild_resource:
            findings.append(
                {
                    "rule_id": "IAC_IAM_ADMIN_PRIVILEGE",
                    "severity": "critical",
                    "title": "IAM policy grants administrative wildcard privileges",
                    "resource": f"{block['type']}.{block['name']}",
                    "file_path": file_path,
                    "evidence": {"admin_action": True, "wildcard_resource": True},
                    "remediation": "Replace wildcard IAM permissions with least-privilege actions and scoped resources.",
                }
            )

    for block in _matching_blocks(text, "aws_iam_policy_attachment") + _matching_blocks(text, "aws_iam_role_policy_attachment") + _matching_blocks(text, "aws_iam_user_policy_attachment") + _matching_blocks(text, "aws_iam_group_policy_attachment"):
        body = block["body"]
        if re.search(r"arn:aws:iam::aws:policy/AdministratorAccess", body, re.IGNORECASE):
            findings.append(
                {
                    "rule_id": "IAC_IAM_ADMIN_POLICY_ATTACHED",
                    "severity": "critical",
                    "title": "AWS AdministratorAccess policy is attached",
                    "resource": f"{block['type']}.{block['name']}",
                    "file_path": file_path,
                    "evidence": {"managed_policy": "AdministratorAccess"},
                    "remediation": "Use a least-privilege customer-managed policy instead of AdministratorAccess.",
                }
            )

    status = "PASS" if not findings else "FAIL"
    return {
        "ok": True,
        "status": status,
        "exit_code": 0 if status == "PASS" else 1,
        "findings": findings,
        "checked_rules": [
            "IAC_AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            "IAC_OPEN_SSH_TO_INTERNET",
            "IAC_IAM_ADMIN_PRIVILEGE",
            "IAC_IAM_ADMIN_POLICY_ATTACHED",
        ],
    }
