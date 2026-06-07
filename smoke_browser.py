import json
import os
import signal
from pathlib import Path

from controllers.patchright_controller import PatchrightController


def _timeout(_signum, _frame):
    raise TimeoutError("smoke timed out")


def main():
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(120)

    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    controller = PatchrightController()
    print(json.dumps({"stage": "launch", "proxy": config.get("proxy")}, ensure_ascii=False), flush=True)
    context = controller.get_thread_browser()
    if not context:
        raise SystemExit(2)

    captures = Path(__file__).resolve().parent / "captures"
    captures.mkdir(exist_ok=True)

    page = None
    try:
        page = context.pages[0] if context.pages else context.new_page()
        page.goto("https://api.ipify.org", timeout=30000, wait_until="domcontentloaded")
        ip_text = page.locator("body").inner_text(timeout=10000).strip()
        page.goto("https://example.com", timeout=30000, wait_until="domcontentloaded")
        title = page.title()
        page.screenshot(path=str(captures / "sandbox_smoke.png"), full_page=True)
        print(json.dumps({
            "ok": True,
            "proxy": config.get("proxy"),
            "browser_path": config.get("patchright", {}).get("browser_path") or os.environ.get("OUTLOOK_BROWSER_PATH", ""),
            "ip": ip_text,
            "title": title,
        }, ensure_ascii=False), flush=True)
    finally:
        controller.clean_up(type="all_browser")
        signal.alarm(0)


if __name__ == "__main__":
    main()
