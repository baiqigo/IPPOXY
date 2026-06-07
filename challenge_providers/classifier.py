from typing import Any, Dict


def _safe_count(locator) -> int:
    try:
        return locator.count()
    except Exception:
        return 0


def classify_challenge(page) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {
        "type": "unknown",
        "url": "",
        "title": "",
        "frames": [],
        "iframe_elements": [],
        "signals": {},
    }

    try:
        evidence["url"] = page.url
    except Exception as e:
        evidence["url_error"] = repr(e)

    try:
        evidence["title"] = page.title(timeout=3000)
    except Exception as e:
        evidence["title_error"] = repr(e)

    try:
        for frame in page.frames:
            evidence["frames"].append({
                "name": frame.name,
                "url": frame.url,
            })
    except Exception as e:
        evidence["frames_error"] = repr(e)

    try:
        iframe_handles = page.query_selector_all("iframe")
        for idx, iframe in enumerate(iframe_handles[:30]):
            try:
                meta = iframe.evaluate(
                    """e => ({
                        id: e.id,
                        name: e.getAttribute('name'),
                        title: e.getAttribute('title'),
                        src: e.getAttribute('src'),
                        style: e.getAttribute('style'),
                        box: (() => {
                            const r = e.getBoundingClientRect();
                            return {x: r.x, y: r.y, width: r.width, height: r.height};
                        })()
                    })"""
                )
            except Exception as e:
                meta = {"error": repr(e)}
            meta["index"] = idx
            evidence["iframe_elements"].append(meta)
    except Exception as e:
        evidence["iframe_elements_error"] = repr(e)

    page_text = ""
    try:
        page_text = page.locator("body").inner_text(timeout=3000)[:5000]
    except Exception:
        pass

    frame_urls = " ".join((f.get("url") or "") for f in evidence["frames"]).lower()
    iframe_blob = " ".join(
        " ".join(str(v or "") for v in item.values())
        for item in evidence["iframe_elements"]
    ).lower()
    blob = f"{frame_urls} {iframe_blob} {page_text.lower()}"

    signals = {
        "microsoft_challenge_frame": _safe_count(page.locator('iframe[title="验证质询"]')),
        "enforcement_frame": _safe_count(page.locator("iframe#enforcementFrame")),
        "hcaptcha": int("hcaptcha" in blob),
        "recaptcha": int("recaptcha" in blob or "google.com/recaptcha" in blob),
        "turnstile": int("turnstile" in blob or "challenges.cloudflare.com" in blob),
        "arkose": int("arkose" in blob or "funcaptcha" in blob or "client-api.arkoselabs" in blob),
    }
    evidence["signals"] = signals

    if signals["microsoft_challenge_frame"]:
        evidence["type"] = "microsoft_press"
    elif signals["arkose"] or signals["enforcement_frame"]:
        evidence["type"] = "arkose_funcaptcha"
    elif signals["hcaptcha"]:
        evidence["type"] = "hcaptcha"
    elif signals["recaptcha"]:
        evidence["type"] = "recaptcha"
    elif signals["turnstile"]:
        evidence["type"] = "turnstile"
    else:
        evidence["type"] = "unknown"

    return evidence
