# Shows which browser origins our API trusts.

import httpx

BASE = "http://127.0.0.1:8000"

def preflight(origin, header):
    """Pretend to be a browser asking: may this origin send a GET with this header?"""
    r = httpx.options(
        f"{BASE}/transactions/me",
        headers={
            "Origin": origin,                                  # which website is asking
            "Access-Control-Request-Method": "GET",            # the method it wants to use
            "Access-Control-Request-Headers": header,          # the header it wants to send
        },
        timeout=30,
    )
    allowed = r.headers.get("access-control-allow-origin")    # present only if trusted
    print(f"{origin:25} + {header:13} -> {r.status_code}  allow-origin: {allowed}")
    print("     reason:", r.text)


preflight("http://localhost:3000", "authorization")   # our frontend + a token: allowed
preflight("https://evil-site.com", "authorization")   # unknown website: blocked
preflight("http://localhost:3000", "x-api-key")       # our frontend trying to send an API key: blocked


# A normal GET from an unknown origin still get an answer, but without the allow header
# so a browser would refuse to show it to evil-site's JavaScript.
r = httpx.get(f"{BASE}/health", headers={"Origin": "https://evil-site.com"}, timeout=30)
print("\nGET /health from evil-site ->", r.status_code, "allow-origin:", r.headers.get("access-control-allow-origin"))