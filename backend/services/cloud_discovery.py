"""
Cloud Asset Discovery — AWS · GCP · Azure

Discovers TLS-bearing endpoints from cloud provider APIs and returns
them as a list of targets ready for post-quantum scanning.

All implementations use only stdlib (urllib + hashlib + hmac + base64).
boto3 / google-auth / azure-identity are NOT required.

AWS:   SigV4-signed requests to EC2, ELBv2, CloudFront, API Gateway
GCP:   REST API with service-account JWT (RS256 via cryptography if available,
        else HS256 warning — user should use cryptography lib in prod)
Azure: OAuth2 client-credentials flow + Management REST API
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _http_get(url: str, headers: Dict[str, str] = None, timeout: int = 12) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:300]
        except Exception: pass
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def _http_post(url: str, data: dict, headers: Dict[str, str] = None, timeout: int = 12) -> Dict[str, Any]:
    payload = urllib.parse.urlencode(data).encode()
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:300]
        except Exception: pass
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


# ── AWS SigV4 signing ──────────────────────────────────────────────────────────

def _aws_sign_request(
    method: str,
    service: str,
    region: str,
    host: str,
    path: str,
    query: str,
    payload: bytes,
    access_key: str,
    secret_key: str,
    session_token: str = "",
) -> Dict[str, str]:
    """Compute AWS SigV4 Authorization header + required headers."""
    now = datetime.now(timezone.utc)
    amz_date  = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(payload).hexdigest()

    headers_to_sign = {"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    if session_token:
        headers_to_sign["x-amz-security-token"] = session_token

    signed_headers = ";".join(sorted(headers_to_sign))
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers_to_sign.items()))
    canonical_request = "\n".join([method, path, query, canonical_headers, signed_headers, payload_hash])

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(_sign(_sign(_sign(
        f"AWS4{secret_key}".encode(), date_stamp), region), service), "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    result = {
        "Authorization":        auth,
        "X-Amz-Date":           amz_date,
        "X-Amz-Content-Sha256": payload_hash,
    }
    if session_token:
        result["X-Amz-Security-Token"] = session_token
    return result


def _aws_get(
    service: str, region: str, path: str, params: Dict[str, str],
    access_key: str, secret_key: str, session_token: str = "",
) -> Dict[str, Any]:
    host = f"{service}.{region}.amazonaws.com"
    query = urllib.parse.urlencode(sorted(params.items()))
    hdrs = _aws_sign_request("GET", service, region, host, path, query, b"",
                             access_key, secret_key, session_token)
    hdrs["Host"] = host
    url = f"https://{host}{path}?{query}"
    return _http_get(url, headers=hdrs)


# ── AWS Discovery ──────────────────────────────────────────────────────────────

def _discover_aws_ec2(access_key: str, secret_key: str, regions: List[str], token: str = "") -> List[Dict]:
    targets = []
    for region in regions:
        try:
            resp = _aws_get("ec2", region, "/", {
                "Action": "DescribeInstances",
                "Version": "2016-11-15",
                "Filter.1.Name": "instance-state-name",
                "Filter.1.Value.1": "running",
            }, access_key, secret_key, token)
            # Parse XML — instances have PublicDnsName
            dns_names = re.findall(r"<publicDnsName>([^<]+)</publicDnsName>", str(resp))
            for dns in dns_names:
                if dns.strip():
                    targets.append({"host": dns, "port": 443, "source": f"aws:ec2:{region}", "asset_type": "ec2"})
        except Exception as ex:
            targets.append({"error": str(ex)[:150], "source": f"aws:ec2:{region}"})
    return targets


def _discover_aws_elb(access_key: str, secret_key: str, regions: List[str], token: str = "") -> List[Dict]:
    targets = []
    for region in regions:
        try:
            resp = _aws_get("elasticloadbalancing", region, "/", {
                "Action": "DescribeLoadBalancers",
                "Version": "2015-12-01",
            }, access_key, secret_key, token)
            dns_names = re.findall(r"<DNSName>([^<]+)</DNSName>", str(resp))
            for dns in dns_names:
                if dns.strip():
                    targets.append({"host": dns, "port": 443, "source": f"aws:elb:{region}", "asset_type": "elb"})
        except Exception as ex:
            targets.append({"error": str(ex)[:150], "source": f"aws:elb:{region}"})
    return targets


def _discover_aws_cloudfront(access_key: str, secret_key: str, token: str = "") -> List[Dict]:
    targets = []
    try:
        host = "cloudfront.amazonaws.com"
        path = "/2020-05-31/distribution"
        query = ""
        hdrs = _aws_sign_request("GET", "cloudfront", "us-east-1", host, path, query, b"",
                                 access_key, secret_key, token)
        hdrs["Host"] = host
        url = f"https://{host}{path}"
        resp_raw = ""
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=12) as r:
            resp_raw = r.read().decode()
        domains = re.findall(r"<DomainName>([^<]+\.cloudfront\.net)</DomainName>", resp_raw)
        for d in domains:
            targets.append({"host": d, "port": 443, "source": "aws:cloudfront", "asset_type": "cloudfront"})
    except Exception as ex:
        targets.append({"error": str(ex)[:150], "source": "aws:cloudfront"})
    return targets


def discover_aws(
    access_key_id: str,
    secret_access_key: str,
    session_token: str = "",
    regions: Optional[List[str]] = None,
    include_cloudfront: bool = True,
    include_ec2: bool = True,
    include_elb: bool = True,
) -> Dict[str, Any]:
    """
    Discover TLS-bearing endpoints from AWS.

    Returns a list of targets {host, port, source, asset_type}
    ready to feed into Morrow's scanner.
    """
    regions = regions or ["us-east-1", "us-west-2", "eu-west-1"]
    targets: List[Dict] = []
    errors: List[str] = []

    if include_ec2:
        for t in _discover_aws_ec2(access_key_id, secret_access_key, regions, session_token):
            (errors if "error" in t else targets).append(t)
    if include_elb:
        for t in _discover_aws_elb(access_key_id, secret_access_key, regions, session_token):
            (errors if "error" in t else targets).append(t)
    if include_cloudfront:
        for t in _discover_aws_cloudfront(access_key_id, secret_access_key, session_token):
            (errors if "error" in t else targets).append(t)

    return {
        "provider": "aws",
        "targets": targets,
        "target_count": len(targets),
        "errors": errors,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


# ── GCP Discovery ──────────────────────────────────────────────────────────────

def _gcp_get_access_token(service_account_json: Dict[str, Any]) -> str:
    """Obtain a GCP access token via the metadata server or service-account JWT."""
    # Try metadata server (works on GCE/Cloud Run/Cloud Functions)
    try:
        meta_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        req = urllib.request.Request(meta_url, headers={"Metadata-Flavor": "Google"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read().decode()).get("access_token", "")
    except Exception:
        pass

    # Fall back to service-account JWT → exchange for access token
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        import time as _time

        priv_key_pem = service_account_json["private_key"].encode()
        private_key = serialization.load_pem_private_key(priv_key_pem, password=None)
        client_email = service_account_json["client_email"]
        token_uri = service_account_json.get("token_uri", "https://oauth2.googleapis.com/token")

        now = int(_time.time())
        header = base64.urlsafe_b64encode(json.dumps({"alg":"RS256","typ":"JWT"}).encode()).rstrip(b"=")
        claims = base64.urlsafe_b64encode(json.dumps({
            "iss": client_email, "sub": client_email,
            "aud": token_uri,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "iat": now, "exp": now + 3600,
        }).encode()).rstrip(b"=")
        msg = header + b"." + claims
        sig = base64.urlsafe_b64encode(private_key.sign(msg, _padding.PKCS1v15(), hashes.SHA256())).rstrip(b"=")
        jwt = msg + b"." + sig

        token_resp = _http_post(token_uri, {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt.decode(),
        })
        return token_resp.get("access_token", "")
    except Exception as ex:
        raise RuntimeError(f"Cannot get GCP access token: {ex}") from ex


def discover_gcp(
    project_id: str,
    service_account_json: Optional[Dict[str, Any]] = None,
    include_compute: bool = True,
    include_run: bool = True,
    include_lb: bool = True,
) -> Dict[str, Any]:
    """
    Discover TLS-bearing endpoints from GCP.

    service_account_json: parsed content of a service account JSON key file.
    If None, uses the GCE metadata server (works inside GCP).
    """
    targets: List[Dict] = []
    errors: List[str] = []

    try:
        token = _gcp_get_access_token(service_account_json or {})
    except Exception as ex:
        return {"provider": "gcp", "targets": [], "target_count": 0,
                "errors": [str(ex)], "discovered_at": datetime.now(timezone.utc).isoformat()}

    auth_hdrs = {"Authorization": f"Bearer {token}"}

    # Compute Engine instances
    if include_compute:
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances?filter=status%3DRUNNING"
            resp = _http_get(url, headers=auth_hdrs)
            for zone_data in resp.get("items", {}).values():
                for inst in zone_data.get("instances", []):
                    for iface in inst.get("networkInterfaces", []):
                        for ac in iface.get("accessConfigs", []):
                            ip = ac.get("natIP", "")
                            if ip:
                                targets.append({"host": ip, "port": 443,
                                                "source": f"gcp:compute:{zone_data.get('id','')}",
                                                "asset_type": "compute", "name": inst.get("name","")})
        except Exception as ex:
            errors.append(f"gcp:compute: {str(ex)[:150]}")

    # Cloud Run services
    if include_run:
        try:
            url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/-/services"
            resp = _http_get(url, headers=auth_hdrs)
            for svc in resp.get("services", []):
                uri = svc.get("uri", "")
                if uri:
                    host = uri.replace("https://","").replace("http://","").split("/")[0]
                    targets.append({"host": host, "port": 443, "source": "gcp:cloud_run",
                                    "asset_type": "cloud_run", "name": svc.get("name","").split("/")[-1]})
        except Exception as ex:
            errors.append(f"gcp:cloud_run: {str(ex)[:150]}")

    # Load balancer forwarding rules
    if include_lb:
        try:
            url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/forwardingRules?filter=IPProtocol%3DTCP"
            resp = _http_get(url, headers=auth_hdrs)
            for rule in resp.get("items", []):
                ip = rule.get("IPAddress", "")
                port = rule.get("portRange", "443").split("-")[0]
                if ip and port in ("443", "8443"):
                    targets.append({"host": ip, "port": int(port), "source": "gcp:load_balancer",
                                    "asset_type": "load_balancer", "name": rule.get("name","")})
        except Exception as ex:
            errors.append(f"gcp:lb: {str(ex)[:150]}")

    return {
        "provider": "gcp",
        "targets": targets,
        "target_count": len(targets),
        "errors": errors,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Azure Discovery ────────────────────────────────────────────────────────────

def _azure_get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = _http_post(url, {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
    })
    return resp.get("access_token", "")


def discover_azure(
    subscription_id: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    include_app_gateways: bool = True,
    include_public_ips: bool = True,
    include_app_services: bool = True,
) -> Dict[str, Any]:
    """Discover TLS-bearing endpoints from Azure subscription."""
    targets: List[Dict] = []
    errors: List[str] = []

    try:
        token = _azure_get_token(tenant_id, client_id, client_secret)
    except Exception as ex:
        return {"provider": "azure", "targets": [], "target_count": 0,
                "errors": [str(ex)], "discovered_at": datetime.now(timezone.utc).isoformat()}

    auth_hdrs = {"Authorization": f"Bearer {token}"}
    base = f"https://management.azure.com/subscriptions/{subscription_id}"

    # Application Gateways
    if include_app_gateways:
        try:
            url = f"{base}/providers/Microsoft.Network/applicationGateways?api-version=2023-02-01"
            resp = _http_get(url, headers=auth_hdrs)
            for gw in resp.get("value", []):
                props = gw.get("properties", {})
                for fe_ip in props.get("frontendIPConfigurations", []):
                    pip = fe_ip.get("properties", {}).get("publicIPAddress", {})
                    if pip:
                        targets.append({"host": pip.get("id","").split("/")[-1],
                                        "port": 443, "source": "azure:app_gateway",
                                        "asset_type": "app_gateway", "name": gw.get("name","")})
        except Exception as ex:
            errors.append(f"azure:app_gateway: {str(ex)[:150]}")

    # Public IP addresses
    if include_public_ips:
        try:
            url = f"{base}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-02-01"
            resp = _http_get(url, headers=auth_hdrs)
            for pip in resp.get("value", []):
                props = pip.get("properties", {})
                fqdn = props.get("dnsSettings", {}).get("fqdn", "")
                ip   = props.get("ipAddress", "")
                host = fqdn or ip
                if host:
                    targets.append({"host": host, "port": 443, "source": "azure:public_ip",
                                    "asset_type": "public_ip", "name": pip.get("name","")})
        except Exception as ex:
            errors.append(f"azure:public_ip: {str(ex)[:150]}")

    # App Services (Web Apps)
    if include_app_services:
        try:
            url = f"{base}/providers/Microsoft.Web/sites?api-version=2022-03-01"
            resp = _http_get(url, headers=auth_hdrs)
            for site in resp.get("value", []):
                hostname = site.get("properties", {}).get("defaultHostName", "")
                if hostname:
                    targets.append({"host": hostname, "port": 443, "source": "azure:app_service",
                                    "asset_type": "app_service", "name": site.get("name","")})
        except Exception as ex:
            errors.append(f"azure:app_service: {str(ex)[:150]}")

    return {
        "provider": "azure",
        "targets": targets,
        "target_count": len(targets),
        "errors": errors,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Unified discovery summary ──────────────────────────────────────────────────

def aggregate_discovery(*results: Dict[str, Any]) -> Dict[str, Any]:
    """Merge results from multiple cloud provider discoveries."""
    all_targets: List[Dict] = []
    all_errors: List[str] = []
    providers: List[str] = []

    for r in results:
        if not r:
            continue
        all_targets.extend(r.get("targets", []))
        all_errors.extend(r.get("errors", []))
        if r.get("provider"):
            providers.append(r["provider"])

    by_type: Dict[str, int] = {}
    for t in all_targets:
        k = t.get("asset_type", "unknown")
        by_type[k] = by_type.get(k, 0) + 1

    return {
        "providers": providers,
        "total_targets": len(all_targets),
        "targets": all_targets,
        "by_asset_type": by_type,
        "errors": all_errors,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }
