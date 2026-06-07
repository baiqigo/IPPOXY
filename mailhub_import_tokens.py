import argparse
import json
from pathlib import Path

from mailhub_client import import_outlook_account


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "Results"


def _parse_token_line(line):
    parts = line.rstrip("\n").split("---")
    if len(parts) < 4:
        return None
    email, password, refresh_token = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not email or not password or not refresh_token:
        return None
    return {
        "email": email,
        "password": password,
        "refresh_token": refresh_token,
    }


def load_token_accounts(path):
    if not path.exists():
        return []
    seen = set()
    accounts = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        item = _parse_token_line(line)
        if not item:
            continue
        key = item["email"].lower()
        if key in seen:
            continue
        seen.add(key)
        accounts.append(item)
    return accounts


def mask_email(email):
    if "@" not in email:
        return "<invalid-email>"
    prefix, domain = email.split("@", 1)
    return f"{prefix[:3]}***@{domain}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=str(RESULTS / "outlook_token.txt"))
    parser.add_argument("--email", default="")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with open(ROOT / "config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
    client_id = config["oauth2"]["client_id"].strip()

    accounts = load_token_accounts(Path(args.path))
    if args.email:
        wanted = args.email.strip().lower()
        accounts = [item for item in accounts if item["email"].lower() == wanted]
    accounts = accounts[: args.limit]

    print(f"[MailHubBackfill] - candidates={len(accounts)} dry_run={args.dry_run}", flush=True)
    success = 0
    for item in accounts:
        if args.dry_run:
            result = {"enabled": True, "ok": True, "dry_run": True}
        else:
            result = import_outlook_account(
                item["email"],
                item["password"],
                client_id,
                item["refresh_token"],
            )
        public_result = dict(result)
        data = public_result.get("data")
        if isinstance(data, dict):
            public_result["data"] = {
                key: data.get(key)
                for key in ("imported", "duplicated", "skipped", "total", "success")
                if key in data
            }
        print(
            f"[MailHubBackfill] - email={mask_email(item['email'])} "
            f"ok={public_result.get('ok')} result={public_result}",
            flush=True,
        )
        if result.get("ok") or not result.get("enabled"):
            success += 1
    print(f"[MailHubBackfill] - success={success}/{len(accounts)}", flush=True)
    return 0 if success == len(accounts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
