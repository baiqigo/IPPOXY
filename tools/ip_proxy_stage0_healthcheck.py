#!/usr/bin/env python3
"""Stage 0 healthcheck: test subscription candidates through Xray and classify exit IPs."""

from __future__ import annotations

import argparse, base64, hashlib, json, os, re, subprocess, sys, time
from collections import Counter
from pathlib import Path

ROOT = Path(os.environ.get('IPPOXY_ROOT', Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get('IP_PROXY_RUNTIME_DIR', ROOT / '.runtime/ip-proxy'))
RESEARCH_DIR = RUNTIME / 'research'
RESIN_DIR = RUNTIME / 'resin'
BASE_PORT = int(os.environ.get('IP_PROXY_STAGE0_BASE_PORT', '20000'))
DEFAULT_BATCH_SIZE = int(os.environ.get('IP_PROXY_STAGE0_BATCH_SIZE', '50'))
DEFAULT_TIMEOUT = int(os.environ.get('IP_PROXY_STAGE0_TIMEOUT', '8'))
DEFAULT_CONTAINER_NAME = 'ippoxy-stage0-check'
XRAY_IMAGE = os.environ.get('IP_PROXY_XRAY_IMAGE', 'ghcr.io/xtls/xray-core:latest')
SUPPORTED_KINDS = {'vless', 'vmess', 'trojan', 'ss'}
# Xray-core supported SS cipher methods (rc4-md5, aes-*-cfb etc. are NOT supported)
XRAY_SS_CIPHERS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
                   'xchacha20-poly1305', '2022-blake3-aes-128-gcm',
                   '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
                   'none', 'plain'}

def parse_vless(raw):
    try:
        raw = raw.strip()
        if not raw.startswith('vless://'):
            return None
        rest = raw[len('vless://'):]
        frag = ''
        if '#' in rest:
            rest, frag = rest.rsplit('#', 1)
        query = ''
        if '?' in rest:
            rest, query = rest.split('?', 1)
        if '@' not in rest:
            return None
        uuid_part, hostport = rest.rsplit('@', 1)
        host, port = hostport.rsplit(':', 1)
        port = int(port)
        params = {}
        if query:
            for p in query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = v
        net = params.get('type', 'tcp')
        security = params.get('security', 'none')
        outbound = {
            'protocol': 'vless',
            'settings': {'vnext': [{'address': host, 'port': port,
                'users': [{'id': uuid_part, 'encryption': params.get('encryption', 'none'),
                           'flow': params.get('flow', '')}]}]},
            'tag': '',
        }
        stream = {'network': net}
        if net == 'ws':
            ws = {'path': params.get('path', '/')}
            if params.get('host'):
                ws['headers'] = {'Host': params['host']}
            stream['wsSettings'] = ws
        elif net == 'grpc':
            stream['grpcSettings'] = {'serviceName': params.get('serviceName', '')}
        elif net == 'tcp' and params.get('headerType') == 'http':
            stream['tcpSettings'] = {'header': {'type': 'http',
                'request': {'headers': {'Host': [params.get('host', '')]}}}}
        if security == 'tls':
            tls = {'allowInsecure': params.get('allowInsecure', '0') == '1'}
            sni = params.get('sni') or params.get('peer')
            if sni:
                tls['serverName'] = sni
            fp = params.get('fp')
            if fp:
                tls['fingerprint'] = fp
            alpn = params.get('alpn')
            if alpn:
                tls['alpn'] = alpn.split(',')
            stream['tlsSettings'] = tls
        elif security == 'reality':
            reality = {}
            pbk = params.get('pbk')
            if pbk:
                reality['publicKey'] = pbk
            sid = params.get('sid')
            if sid:
                reality['shortId'] = sid
            sni = params.get('sni') or params.get('peer')
            if sni:
                reality['serverName'] = sni
            fp = params.get('fp')
            if fp:
                reality['fingerprint'] = fp
            stream['realitySettings'] = reality
        outbound['streamSettings'] = stream
        return {'kind': 'vless', 'protocol': 'vless', 'raw': raw, 'host': host, 'port': port, 'outbound': outbound}
    except Exception:
        return None

def parse_vmess(raw):
    try:
        raw = raw.strip()
        if not raw.startswith('vmess://'):
            return None
        b64 = raw[len('vmess://'):]
        pad = 4 - len(b64) % 4
        if pad < 4:
            b64 += '=' * pad
        decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
        cfg = json.loads(decoded)
        net = cfg.get('net', 'tcp')
        host = cfg.get('add', '')
        port = int(cfg.get('port', 0))
        outbound = {
            'protocol': 'vmess',
            'settings': {'vnext': [{'address': host, 'port': port,
                'users': [{'id': cfg.get('id', ''), 'alterId': int(cfg.get('aid', 0)),
                           'security': cfg.get('scy', 'auto')}]}]},
            'tag': '',
        }
        stream = {'network': net}
        if net == 'ws':
            ws = {'path': cfg.get('path', '/')}
            if cfg.get('host'):
                ws['headers'] = {'Host': cfg['host']}
            stream['wsSettings'] = ws
        elif net == 'grpc':
            stream['grpcSettings'] = {'serviceName': cfg.get('path', '')}
        elif net == 'tcp' and cfg.get('type') == 'http':
            stream['tcpSettings'] = {'header': {'type': 'http'}}
        tls = cfg.get('tls', '')
        if tls:
            stream['tlsSettings'] = {'allowInsecure': True}
            sni = cfg.get('sni') or cfg.get('host')
            if sni:
                stream['tlsSettings']['serverName'] = sni
        outbound['streamSettings'] = stream
        return {'kind': 'vmess', 'protocol': 'vmess', 'raw': raw, 'host': host, 'port': port, 'outbound': outbound}
    except Exception:
        return None

def parse_trojan(raw):
    try:
        raw = raw.strip()
        if not raw.startswith('trojan://'):
            return None
        rest = raw[len('trojan://'):]
        frag = ''
        if '#' in rest:
            rest, frag = rest.rsplit('#', 1)
        query = ''
        if '?' in rest:
            rest, query = rest.split('?', 1)
        if '@' not in rest:
            return None
        password, hostport = rest.rsplit('@', 1)
        host, port = hostport.rsplit(':', 1)
        port = int(port)
        params = {}
        if query:
            for p in query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = v
        outbound = {
            'protocol': 'trojan',
            'settings': {'servers': [{'address': host, 'port': port, 'password': password}]},
            'tag': '',
        }
        stream = {'network': params.get('type', 'tcp')}
        sni = params.get('sni') or params.get('peer') or host
        stream['tlsSettings'] = {'allowInsecure': params.get('allowInsecure', '0') == '1', 'serverName': sni}
        if stream['network'] == 'ws':
            ws = {'path': params.get('path', '/')}
            if params.get('host'):
                ws['headers'] = {'Host': params['host']}
            stream['wsSettings'] = ws
        elif stream['network'] == 'grpc':
            stream['grpcSettings'] = {'serviceName': params.get('serviceName', '')}
        outbound['streamSettings'] = stream
        return {'kind': 'trojan', 'protocol': 'trojan', 'raw': raw, 'host': host, 'port': port, 'outbound': outbound}
    except Exception:
        return None

def parse_ss(raw):
    try:
        raw = raw.strip()
        if not raw.startswith('ss://'):
            return None
        rest = raw[len('ss://'):]
        frag = ''
        if '#' in rest:
            rest, frag = rest.rsplit('#', 1)
        if '@' in rest:
            userinfo, hostport = rest.rsplit('@', 1)
            try:
                pad = 4 - len(userinfo) % 4
                ui_b64 = userinfo + ('=' * pad if pad < 4 else '')
                decoded = base64.b64decode(ui_b64).decode('utf-8', errors='ignore')
                method, password = decoded.split(':', 1)
            except Exception:
                if ':' in userinfo:
                    method, password = userinfo.split(':', 1)
                else:
                    return None
            host, port = hostport.rsplit(':', 1)
            port = int(port)
        else:
            try:
                pad = 4 - len(rest) % 4
                b64 = rest + ('=' * pad if pad < 4 else '')
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                method, rest2 = decoded.split(':', 1)
                password, hostport = rest2.rsplit('@', 1)
                host, port = hostport.rsplit(':', 1)
                port = int(port)
            except Exception:
                return None
        outbound = {
            'protocol': 'shadowsocks',
            'settings': {'servers': [{'address': host, 'port': port, 'method': method, 'password': password}]},
            'tag': '',
        }
        if method.lower() not in XRAY_SS_CIPHERS:
            return None
        return {'kind': 'ss', 'protocol': 'ss', 'raw': raw, 'host': host, 'port': port, 'outbound': outbound}
    except Exception:
        return None

PARSERS = {'vless': parse_vless, 'vmess': parse_vmess, 'trojan': parse_trojan, 'ss': parse_ss}

def generate_batch_config(candidates, base_port):
    inbounds = []
    outbounds = []
    rules = []
    for i, c in enumerate(candidates):
        port = base_port + i
        tag_in = f'in_{i}'
        tag_out = f'out_{i}'
        ib = {'tag': tag_in, 'port': port, 'listen': '127.0.0.1',
              'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}
        ob = dict(c['outbound'])
        ob['tag'] = tag_out
        inbounds.append(ib)
        outbounds.append(ob)
        rules.append({'type': 'field', 'inboundTag': [tag_in], 'outboundTag': tag_out})
    outbounds.append({'protocol': 'freedom', 'tag': 'direct'})
    rules.append({'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'direct'})
    return {'log': {'loglevel': 'warning'}, 'inbounds': inbounds, 'outbounds': outbounds,
            'routing': {'rules': rules}}


def check_exit_ip(socks_port, timeout=8):
    cmd = ['curl', '-sS', '--max-time', str(timeout),
           '--socks5-hostname', f'127.0.0.1:{socks_port}', 'http://ip-api.com/json/']
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout.decode('utf-8', errors='ignore'))
        if data.get('status') != 'success':
            return None
        return data
    except Exception:
        return None


def classify_exit(ip_info):
    dirty = []
    if ip_info.get('proxy', ''):
        dirty.append('is_proxy')
    if ip_info.get('hosting', False):
        dirty.append('is_datacenter')
    if ip_info.get('vpn', False):
        dirty.append('is_vpn')
    if ip_info.get('tor', False):
        dirty.append('is_tor')
    if ip_info.get('abuser', False):
        dirty.append('is_abuser')
    isp_lower = (ip_info.get('isp', '')).lower()
    org_lower = (ip_info.get('org', '')).lower()
    dc_kw = ['hosting', 'data center', 'datacenter', 'cloud', 'server', 'vps',
             'dedicated', 'colocat', 'cdn', 'digitalocean', 'amazon', 'aws',
             'azure', 'google cloud', 'oracle cloud', 'vultr', 'linode',
             'hetzner', 'ovh', 'contabo', 'scaleway']
    for kw in dc_kw:
        if kw in isp_lower or kw in org_lower:
            if 'is_datacenter' not in dirty:
                dirty.append('is_datacenter')
            break
    if not dirty:
        return 'clean', dirty
    hard = {'is_tor', 'is_abuser', 'is_bogon'}
    if set(dirty) & hard:
        return 'dirty', dirty
    return 'risky', dirty


def docker_start(config_path, container, base_port=20000):
    subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=30)
    cmd = ['docker', 'run', '-d', '--name', container, '--network', 'host',
           '-v', f'{config_path}:/usr/local/etc/xray/config.json:ro', XRAY_IMAGE, 'run', '-config', '/usr/local/etc/xray/config.json']
    result = subprocess.run(cmd, capture_output=True, timeout=60)
    if result.returncode != 0:
        stderr_text = result.stderr.decode('utf-8', errors='ignore')
        print(f'docker run failed: {stderr_text}', file=sys.stderr)
        return False
    # Wait for Xray to start and listen
    for attempt in range(15):
        time.sleep(1)
        result = subprocess.run(['ss', '-tlnp'], capture_output=True, timeout=5)
        output = result.stdout.decode('utf-8', errors='ignore')
        # Check if any of our ports are listening
        if str(base_port) in output:
            print(f'  Xray ready after {attempt+1}s')
            return True
    print('  Xray failed to start listening within 15s', file=sys.stderr)
    docker_stop(container)
    return False


def docker_stop(container):
    subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=30)


def atomic_write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + chr(10), encoding='utf-8')
    tmp.replace(path)

def main():
    parser = argparse.ArgumentParser(description='Stage 0 healthcheck for subscription candidates')
    parser.add_argument('--input', type=Path, default=None)
    parser.add_argument('--run-id', default='')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--base-port', type=int, default=BASE_PORT)
    parser.add_argument('--container', default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--keep-container', action='store_true')
    args = parser.parse_args()

    run_id = args.run_id or time.strftime('stage0_%Y%m%d_%H%M%S')
    input_path = args.input
    if input_path is None:
        latest = RESEARCH_DIR / 'subscription_stage0_raw.latest.json'
        if latest.exists():
            input_path = latest
        else:
            print('No input file found', file=sys.stderr)
            return 1

    raw_data = json.loads(input_path.read_text(encoding='utf-8-sig'))
    if not isinstance(raw_data, list):
        print(f'Expected list, got {type(raw_data).__name__}', file=sys.stderr)
        return 1

    parsed = []
    for item in raw_data:
        kind = item.get('kind', '')
        raw_url = item.get('raw', '')
        if kind not in SUPPORTED_KINDS or not raw_url:
            continue
        parser_fn = PARSERS.get(kind)
        if not parser_fn:
            continue
        result = parser_fn(raw_url)
        if result is not None:
            result['source'] = item.get('source', '')
            result['source_project'] = item.get('source_project', '')
            result['source_url'] = item.get('source_url', '')
            result['dedup_key'] = item.get('dedup_key', '')
            result['format'] = item.get('format', '')
            parsed.append(result)

    print(f'Parsed {len(parsed)}/{len(raw_data)} candidates into Xray configs')
    if not parsed:
        print('No parseable candidates', file=sys.stderr)
        return 1

    all_results = []
    total_batches = (len(parsed) + args.batch_size - 1) // args.batch_size
    config_dir = RUNTIME / 'stage0_xray_configs'
    config_dir.mkdir(parents=True, exist_ok=True)

    for batch_idx in range(total_batches):
        start = batch_idx * args.batch_size
        end = min(start + args.batch_size, len(parsed))
        batch = parsed[start:end]
        batch_port_base = args.base_port + start
        print(f'Batch {batch_idx+1}/{total_batches}: {len(batch)} candidates (ports {batch_port_base}-{batch_port_base+len(batch)-1})')

        config = generate_batch_config(batch, batch_port_base)
        config_path = config_dir / f'stage0_batch_{batch_idx}.json'
        atomic_write_json(config_path, config)

        if not docker_start(str(config_path), args.container, batch_port_base):
            print(f'Failed to start container for batch {batch_idx+1}', file=sys.stderr)
            for c in batch:
                all_results.append({'kind': c['kind'], 'protocol': c['protocol'], 'raw': c['raw'],
                    'host': c['host'], 'port': c['port'], 'exit_ip': '', 'success': False,
                    'dirty': ['dead'], 'registration_tier': 'dirty',
                    'source': c.get('source', ''), 'source_project': c.get('source_project', ''),
                    'dedup_key': c.get('dedup_key', '')})
            continue

        for i, c in enumerate(batch):
            port = batch_port_base + i
            ip_info = check_exit_ip(port, args.timeout)
            if ip_info is None:
                tier, dirty = 'dirty', ['dead']
                exit_ip = country = city = company = company_type = asn_type = isp = org = ''
                response_time = -1
            else:
                tier, dirty = classify_exit(ip_info)
                exit_ip = ip_info.get('query', '')
                country = ip_info.get('country', '')
                city = ip_info.get('city', '')
                company = ip_info.get('org', '')
                isp = ip_info.get('isp', '')
                org = ip_info.get('org', '')
                response_time = -1
                hosting_or_dc = ip_info.get('hosting') or any(
                    kw in (isp + org).lower() for kw in ['hosting', 'data center', 'datacenter', 'cloud', 'server', 'vps', 'cdn'])
                if hosting_or_dc:
                    company_type = 'hosting'
                    asn_type = 'hosting'
                elif ip_info.get('isp', ''):
                    company_type = 'isp'
                    asn_type = 'isp'
                else:
                    company_type = 'business'
                    asn_type = 'business'

            all_results.append({'kind': c['kind'], 'protocol': c['protocol'], 'raw': c['raw'],
                'host': c['host'], 'port': c['port'], 'exit_ip': exit_ip,
                'success': ip_info is not None, 'dirty': dirty, 'registration_tier': tier,
                'country': country, 'city': city, 'company': company,
                'company_type': company_type, 'asn_type': asn_type,
                'isp': isp, 'org': org, 'responseTime': response_time,
                'source': c.get('source', ''), 'source_project': c.get('source_project', ''),
                'source_url': c.get('source_url', ''), 'dedup_key': c.get('dedup_key', ''),
                'format': c.get('format', '')})
            ch = '.' if tier == 'clean' else ('~' if tier == 'risky' else 'x')
            sys.stdout.write(ch)
            sys.stdout.flush()

        print()
        if not args.keep_container and batch_idx < total_batches - 1:
            docker_stop(args.container)

    if not args.keep_container:
        docker_stop(args.container)

    RESEARCH_DIR.mkdir(parents=True, exist_ok=True)
    RESIN_DIR.mkdir(parents=True, exist_ok=True)

    out_check = RESEARCH_DIR / f'proxy_candidate_check_{run_id}.json'
    atomic_write_json(out_check, all_results)
    atomic_write_json(RESEARCH_DIR / 'proxy_candidate_check.latest.json', all_results)

    clean = [r for r in all_results if r['registration_tier'] == 'clean']
    relaxed = [r for r in all_results if r['registration_tier'] in {'clean', 'risky'}]
    dirty_list = [r for r in all_results if r['registration_tier'] == 'dirty']

    for r in clean + relaxed + dirty_list:
        ct = (r.get('company_type') or '').lower()
        at = (r.get('asn_type') or '').lower()
        if ct == 'isp' and at == 'isp':
            r['pool_bucket'] = 'residential'
        elif 'hosting' in {ct, at}:
            r['pool_bucket'] = 'risk_review'
        else:
            r['pool_bucket'] = 'static'
        r['registration_eligible'] = r['registration_tier'] in {'clean', 'risky'}

    atomic_write_json(RESIN_DIR / f'clean_candidates_classified_{run_id}.json', clean)
    atomic_write_json(RESIN_DIR / f'relaxed_candidates_classified_{run_id}.json', relaxed)
    atomic_write_json(RESIN_DIR / f'dirty_candidates_classified_{run_id}.json', dirty_list)
    atomic_write_json(RESIN_DIR / f'all_candidates_classified_{run_id}.json', all_results)

    if clean:
        atomic_write_json(RESIN_DIR / 'clean_candidates_classified.latest.json', clean)
        print(f'Updated clean_candidates_classified.latest.json with {len(clean)} clean')
    if relaxed:
        atomic_write_json(RESIN_DIR / 'relaxed_candidates_classified.latest.json', relaxed)
        print(f'Updated relaxed_candidates_classified.latest.json with {len(relaxed)} relaxed')

    tier_counts = Counter(r['registration_tier'] for r in all_results)
    print()
    print('=== Stage 0 Healthcheck Summary ===')
    print(f'Input: {len(raw_data)} raw candidates')
    print(f'Parsed: {len(parsed)} Xray configs')
    print(f'Tested: {len(all_results)}')
    print(f'Clean: {tier_counts.get("clean", 0)}')
    print(f'Risky: {tier_counts.get("risky", 0)}')
    print(f'Dirty: {tier_counts.get("dirty", 0)}')
    if clean:
        cc = Counter(r['country'] for r in clean)
        print(f'Clean countries: {dict(cc.most_common(10))}')
    print(f'Output: {out_check}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
