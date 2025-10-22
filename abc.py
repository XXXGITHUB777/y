import requests
import yaml
import os

os.makedirs("docs", exist_ok=True)

url = "https://raw.githubusercontent.com/ppmm52111/QX/main/SiHai.yaml"
response = requests.get(url, timeout=20)

def bool_str(v):
    return "true" if v else "false"

if response.status_code != 200:
    print("Failed to fetch SiHai.yaml", response.status_code)
    raise SystemExit(1)

yaml_content = yaml.safe_load(response.text)
proxies = yaml_content.get("proxies", [])

qx_lines = []

for item in proxies:
    name = item.get("name", "default_name")
    node_type = item.get("type", "").lower()
    server = item.get("server", "")
    port = item.get("port", "")
    tag = name

    def g(k, default=None):
        return item.get(k, default)

    if node_type == "vmess":
        uuid = g("uuid", "")
        alter = g("alterId", g("alter-id", ""))
        cipher = g("cipher", g("method", "auto"))
        udp = g("udp", False)
        tls = g("tls", False)
        skip_cert = g("skip-cert-verify", False)
        network = g("network", g("net", ""))
        ws_opts = g("ws-opts", {}) or {}
        ws_path = ws_opts.get("path") or g("ws-path") or g("ws_path") or ""
        ws_headers = ws_opts.get("headers", {}) or g("ws-headers") or {}
        if isinstance(ws_headers, dict):
            host_header = ws_headers.get("Host") or ws_headers.get("host", "")
        else:
            host_header = str(ws_headers) if ws_headers else ""

        parts = [
            f"vmess={server}:{port}",
            f"id={uuid}",
        ]
        if alter != "":
            parts.append(f"alter-id={alter}")
        parts.append(f"method={cipher}")
        if udp:
            parts.append(f"udp={bool_str(True)}")
        if tls:
            parts.append(f"tls={bool_str(True)}")
        parts.append(f"skip-cert-verify={bool_str(bool(skip_cert))}")
        if network == "ws" or ws_path:
            parts.append("ws=true")
            if ws_path:
                parts.append(f"ws-path={ws_path}")
            if host_header:
                parts.append(f"ws-headers={{Host: {host_header}}}")
        parts.append(f"tag={tag}")
        qx_lines.append(", ".join(parts))

    elif node_type == "trojan":
        password = g("password", "")
        over_tls = True
        skip_cert = g("skip-cert-verify", False)
        tls_verification = not bool(skip_cert)
        udp_relay = g("udp-relay", None)
        if udp_relay is None:
            udp_relay = True
        sni = g("sni", "")
        obfs = g("obfs", None)
        obfs_host = g("obfs-host", "") or g("ws-headers", {}).get("Host", "")
        parts = [f"trojan={server}:{port}", f"password={password}"]
        parts.append("over-tls=true")
        parts.append(f"tls-verification={bool_str(False)}")
        parts.append(f"udp-relay={bool_str(bool(udp_relay))}")
        if sni:
            parts.append(f"sni={sni}")
        if obfs:
            parts.append(f"obfs={obfs}")
            if obfs_host:
                parts.append(f"obfs-host={obfs_host}")
        parts.append(f"tag={tag}")
        qx_lines.append(", ".join(parts))

    elif node_type == "shadowsocks":
        password = g("password", "")
        method = g("method", "aes-256-gcm")
        udp = g("udp", False)
        parts = [f"shadowsocks={server}:{port}", f"method={method}", f"password={password}", f"udp-relay={bool_str(udp)}", f"tag={tag}"]
        qx_lines.append(", ".join(parts))

    elif node_type == "vless":
        uuid = g("uuid", g("id", ""))
        over_tls = True
        skip_cert = g("skip-cert-verify", False)
        tls_verification = not bool(skip_cert)
        parts = [f"vless={server}:{port}", f"id={uuid}", "method=none"]
        parts.append("over-tls=true")
        parts.append(f"tls-verification={bool_str(tls_verification)}")
        parts.append(f"tag={tag}")
        qx_lines.append(", ".join(parts))

    elif node_type == "http":
        parts = [f"http={server}:{port}", f"tag={tag}"]
        qx_lines.append(", ".join(parts))

    elif node_type == "socks5":
        parts = [f"socks5={server}:{port}", f"tag={tag}"]
        qx_lines.append(", ".join(parts))

    else:
        password = g("password", "")
        cipher = g("cipher", "aes-256-gcm")
        udp = g("udp", False)
        qx_lines.append(f"shadowsocks={server}:{port}, method={cipher}, password={password}, udp={bool_str(udp)}, tag={tag}")

out_path = "docs/123.txt"
with open(out_path, "w", encoding="utf-8") as wf:
    for line in qx_lines:
        wf.write(line + "\n")

print("Wrote", out_path)
