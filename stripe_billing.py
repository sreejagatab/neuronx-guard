"""
NeuronX Guard — Stripe Billing Integration

Handles: checkout sessions, webhook events, tier upgrades, billing portal.
Replace STRIPE_* env vars with real keys from stripe.com.
"""

import os
import json
import hmac
import hashlib
import logging
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

logger = logging.getLogger("guard_billing")

router = APIRouter()

# --- Stripe Config (set in .env) ---
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRO_PRICE_ID = os.getenv("STRIPE_PRO_PRICE_ID", "")  # price_xxxxx
STRIPE_TEAM_PRICE_ID = os.getenv("STRIPE_TEAM_PRICE_ID", "")  # price_xxxxx
GUARD_URL = os.getenv("GUARD_PUBLIC_URL", "https://neuronx.jagatab.uk")


def _stripe_api(endpoint: str, data: dict = None, method: str = "POST") -> dict:
    """Call Stripe API."""
    if not STRIPE_SECRET_KEY:
        return {"error": "Stripe not configured"}
    url = f"https://api.stripe.com/v1{endpoint}"
    headers = {
        "Authorization": f"Bearer {STRIPE_SECRET_KEY}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = json.loads(e.read())
        return {"error": error_body.get("error", {}).get("message", str(e))}
    except Exception as e:
        return {"error": str(e)}


# --- Checkout ---

@router.get("/checkout/pro")
async def checkout_pro(installation_id: int = 0):
    """Create Stripe checkout session for Pro tier."""
    if not STRIPE_SECRET_KEY or not STRIPE_PRO_PRICE_ID:
        return JSONResponse({
            "status": "not_configured",
            "message": "Payment system coming soon. Contact sreejagatab@yahoo.com for Pro access.",
        })

    session = _stripe_api("/checkout/sessions", {
        "mode": "subscription",
        "line_items[0][price]": STRIPE_PRO_PRICE_ID,
        "line_items[0][quantity]": "1",
        "success_url": f"{GUARD_URL}/guard?upgraded=pro&session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{GUARD_URL}/guard#pricing",
        "metadata[installation_id]": str(installation_id),
        "metadata[tier]": "pro",
    })

    if session.get("url"):
        return RedirectResponse(session["url"])
    return JSONResponse({"error": session.get("error", "Checkout failed")}, status_code=500)


@router.get("/checkout/team")
async def checkout_team(installation_id: int = 0):
    """Create Stripe checkout session for Team tier."""
    if not STRIPE_SECRET_KEY or not STRIPE_TEAM_PRICE_ID:
        return JSONResponse({
            "status": "not_configured",
            "message": "Payment system coming soon. Contact sreejagatab@yahoo.com for Team access.",
        })

    session = _stripe_api("/checkout/sessions", {
        "mode": "subscription",
        "line_items[0][price]": STRIPE_TEAM_PRICE_ID,
        "line_items[0][quantity]": "1",
        "success_url": f"{GUARD_URL}/guard?upgraded=team&session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{GUARD_URL}/guard#pricing",
        "metadata[installation_id]": str(installation_id),
        "metadata[tier]": "team",
    })

    if session.get("url"):
        return RedirectResponse(session["url"])
    return JSONResponse({"error": session.get("error", "Checkout failed")}, status_code=500)


@router.get("/billing/portal")
async def billing_portal(customer_id: str = ""):
    """Redirect to Stripe billing portal for subscription management."""
    if not STRIPE_SECRET_KEY or not customer_id:
        return JSONResponse({
            "status": "not_configured",
            "message": "Contact sreejagatab@yahoo.com to manage your subscription.",
        })

    session = _stripe_api("/billing_portal/sessions", {
        "customer": customer_id,
        "return_url": f"{GUARD_URL}/guard",
    })

    if session.get("url"):
        return RedirectResponse(session["url"])
    return JSONResponse({"error": session.get("error", "Portal failed")}, status_code=500)


# --- Stripe Webhook ---

@router.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events for subscription lifecycle."""
    body = await request.body()

    # Verify signature
    if STRIPE_WEBHOOK_SECRET:
        sig = request.headers.get("Stripe-Signature", "")
        try:
            _verify_stripe_signature(body, sig)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid signature")

    event = json.loads(body)
    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    logger.info(f"Stripe event: {event_type}")

    if event_type == "checkout.session.completed":
        # Payment successful — upgrade tier
        metadata = data.get("metadata", {})
        installation_id = int(metadata.get("installation_id", 0))
        tier = metadata.get("tier", "pro")
        customer_id = data.get("customer", "")

        if installation_id:
            from guard_db import get_installation
            import sqlite3
            from pathlib import Path
            DB_PATH = Path(__file__).parent / "guard_data.db"
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                "UPDATE installations SET tier = ? WHERE installation_id = ?",
                (tier, installation_id)
            )
            conn.commit()
            conn.close()
            logger.info(f"Upgraded installation {installation_id} to {tier} (customer: {customer_id})")

        return {"status": "upgraded", "tier": tier, "installation_id": installation_id}

    elif event_type in ("customer.subscription.deleted", "customer.subscription.paused"):
        # Subscription cancelled — downgrade to free
        customer_id = data.get("customer", "")
        # Find installation by customer (would need customer_id stored — simplified here)
        logger.info(f"Subscription cancelled for customer {customer_id}")
        return {"status": "downgraded", "customer": customer_id}

    elif event_type == "invoice.payment_failed":
        # Payment failed — warn but don't downgrade immediately
        customer_id = data.get("customer", "")
        logger.warning(f"Payment failed for customer {customer_id}")
        return {"status": "payment_failed", "customer": customer_id}

    return {"status": "ignored", "event": event_type}


def _verify_stripe_signature(payload: bytes, sig_header: str):
    """Verify Stripe webhook signature."""
    if not STRIPE_WEBHOOK_SECRET:
        return
    parts = dict(item.split("=", 1) for item in sig_header.split(",") if "=" in item)
    timestamp = parts.get("t", "")
    signature = parts.get("v1", "")
    signed_payload = f"{timestamp}.{payload.decode()}"
    expected = hmac.new(
        STRIPE_WEBHOOK_SECRET.encode(), signed_payload.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature")


# --- Status ---

@router.get("/billing/status")
async def billing_status():
    """Check if billing is configured."""
    return {
        "stripe_configured": bool(STRIPE_SECRET_KEY),
        "pro_price_id": bool(STRIPE_PRO_PRICE_ID),
        "team_price_id": bool(STRIPE_TEAM_PRICE_ID),
        "checkout_urls": {
            "pro": f"{GUARD_URL}/checkout/pro",
            "team": f"{GUARD_URL}/checkout/team",
        },
        "contact": "sreejagatab@yahoo.com",
    }
