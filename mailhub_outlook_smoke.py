import argparse
import json
import time
from pathlib import Path

from mailhub_client import (
    acquire_outlook_inbox,
    get_inbox_code,
    get_outlook_stats,
    list_inbox_messages,
    release_inbox,
    report_inbox,
)


def mask_email(value):
    if not value or "@" not in value:
        return value or ""
    prefix, domain = value.split("@", 1)
    return f"{prefix[:3]}***@{domain}"


def safe_identifier(value):
    text = str(value or "")
    if "@" in text:
        return mask_email(text)
    return text


def public_result(result, data_keys=None):
    output = {
        "enabled": result.get("enabled"),
        "ok": result.get("ok"),
        "status": result.get("status"),
    }
    if result.get("error"):
        output["error"] = str(result.get("error"))[:300]
    data = result.get("data")
    if isinstance(data, dict):
        if data_keys:
            safe_data = {}
            for key in data_keys:
                if key not in data:
                    continue
                value = data.get(key)
                if key in ("code", "latest_code"):
                    safe_data[f"{key}_present"] = bool(value)
                elif key == "codes":
                    safe_data["codes_count"] = len(value) if isinstance(value, list) else int(bool(value))
                elif key == "message":
                    safe_data[key] = str(value)[:120]
                elif key in ("email", "address", "id", "inboxId"):
                    safe_data[key] = safe_identifier(value)
                else:
                    safe_data[key] = value
            output["data"] = safe_data
        else:
            output["data_keys"] = sorted(data.keys())[:20]
    return output


def extract_inbox(data):
    if not isinstance(data, dict):
        return {"id": "", "email": ""}
    email = str(data.get("email") or data.get("address") or "")
    inbox_id = str(data.get("id") or data.get("inboxId") or email)
    return {"id": inbox_id, "email": email}


def count_messages(result):
    data = result.get("data")
    if not isinstance(data, dict):
        return 0
    messages = data.get("messages")
    if isinstance(messages, list):
        return len(messages)
    items = data.get("items")
    if isinstance(items, list):
        return len(items)
    return 0


def summarize_stats(result):
    data = result.get("data")
    keys = (
        "total",
        "available",
        "assigned",
        "validToken",
        "invalidToken",
        "pendingOAuth",
        "noToken",
    )
    if isinstance(data, dict):
        return {key: data.get(key) for key in keys if key in data}
    return {}


def run_smoke(
    service="ippoxy-smoke",
    email="",
    inbox_id="",
    keep_inbox=False,
    code_wait=False,
    code_timeout=30,
    code_type="numeric",
    keyword="",
    expect_min_available=-1,
):
    summary = {
        "ok": False,
        "started_at": int(time.time()),
        "service": service,
        "mode": "direct" if (email or inbox_id) else "acquire",
    }

    stats_before = get_outlook_stats()
    summary["stats_before"] = public_result(stats_before)
    summary["stats_before_counts"] = summarize_stats(stats_before)
    if not stats_before.get("enabled"):
        summary["error"] = "MAIL_HUB_URL is not configured"
        return summary, 2

    if expect_min_available >= 0:
        available = summary["stats_before_counts"].get("available")
        if available is None or int(available) < expect_min_available:
            summary["error"] = f"available below expectation: {available} < {expect_min_available}"
            return summary, 1

    acquired = False
    inbox = {"id": inbox_id or email, "email": email}
    if not inbox["id"]:
        acquire_result = acquire_outlook_inbox(service=service)
        summary["acquire"] = public_result(
            acquire_result,
            data_keys=("id", "inboxId", "email", "address", "provider", "expiresAt", "upstreamProvider"),
        )
        if not acquire_result.get("ok"):
            summary["error"] = "acquire failed"
            return summary, 1
        inbox = extract_inbox(acquire_result.get("data"))
        acquired = True

    lookup = inbox["id"] or inbox["email"]
    summary["inbox"] = {
        "id": safe_identifier(lookup),
        "email": mask_email(inbox.get("email", "")),
        "acquired": acquired,
    }

    messages_result = list_inbox_messages(lookup)
    summary["messages"] = public_result(messages_result)
    summary["messages_count"] = count_messages(messages_result)

    code_result = get_inbox_code(
        lookup,
        wait=code_wait,
        code_type=code_type,
        timeout=code_timeout if code_wait else None,
        keyword=keyword,
    )
    summary["code"] = public_result(code_result, data_keys=("code", "codes", "latest_code", "message"))

    success = bool(messages_result.get("ok") and code_result.get("ok"))
    if acquired and not keep_inbox:
        report_result = report_inbox(
            lookup,
            success=success,
            meta={"source": "ippoxy_mailhub_outlook_smoke", "messages_count": summary["messages_count"]},
        )
        summary["report"] = public_result(report_result)
        release_result = release_inbox(lookup)
        summary["release"] = public_result(release_result)

    stats_after = get_outlook_stats()
    summary["stats_after"] = public_result(stats_after)
    summary["stats_after_counts"] = summarize_stats(stats_after)
    summary["ok"] = bool(stats_before.get("ok") and messages_result.get("ok") and code_result.get("ok"))
    if acquired and not keep_inbox:
        summary["ok"] = summary["ok"] and summary.get("release", {}).get("ok", False)
    return summary, 0 if summary["ok"] else 1


def write_report(path, summary):
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Validate the MailHub Outlook pool without creating Outlook accounts."
    )
    parser.add_argument("--service", default="ippoxy-smoke")
    parser.add_argument("--email", default="", help="Probe a specific existing Outlook inbox instead of acquiring one.")
    parser.add_argument("--inbox-id", default="", help="Probe a specific MailHub inbox id instead of acquiring one.")
    parser.add_argument("--keep-inbox", action="store_true", help="Do not report/delete an acquired inbox.")
    parser.add_argument("--code-wait", action="store_true", help="Wait for a code instead of only checking the endpoint.")
    parser.add_argument("--code-timeout", type=int, default=30)
    parser.add_argument("--code-type", default="numeric")
    parser.add_argument("--keyword", default="")
    parser.add_argument("--expect-min-available", type=int, default=-1)
    parser.add_argument("--write-report", default="", help="Write the same redacted JSON summary to this path.")
    args = parser.parse_args()

    summary, exit_code = run_smoke(
        service=args.service,
        email=args.email,
        inbox_id=args.inbox_id,
        keep_inbox=args.keep_inbox,
        code_wait=args.code_wait,
        code_timeout=args.code_timeout,
        code_type=args.code_type,
        keyword=args.keyword,
        expect_min_available=args.expect_min_available,
    )
    write_report(args.write_report, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
