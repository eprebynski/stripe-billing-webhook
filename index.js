// index.js (Cloud Run Stripe webhook forwarder)
// - Verifies Stripe signature using RAW request body
// - Forwards a simplified payload to Apps Script
// - Preserves POST across Apps Script 302/303 redirects (critical)

import express from "express";
import Stripe from "stripe";

const app = express();
const PORT = process.env.PORT || 8080;

const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || "").trim(); // Stripe signing secret (whsec_...)
const APPS_SCRIPT_WEBHOOK_URL = (process.env.APPS_SCRIPT_WEBHOOK_URL || "").trim(); // MUST include ?mode=billingWebhook
const BILLING_WEBHOOK_SHARED_SECRET = (process.env.BILLING_WEBHOOK_SHARED_SECRET || "").trim(); // your own shared secret (NOT Stripe's)

const allowedTypes = new Set(
  (process.env.ALLOWED_EVENT_TYPES || "invoice.paid,invoice.payment_failed,invoice.finalized")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

// Stripe client is only used for webhook signature verification here
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_placeholder", {
  apiVersion: "2024-06-20",
});

if (!STRIPE_WEBHOOK_SECRET) console.warn("Missing STRIPE_WEBHOOK_SECRET");
if (!APPS_SCRIPT_WEBHOOK_URL) console.warn("Missing APPS_SCRIPT_WEBHOOK_URL");
if (!BILLING_WEBHOOK_SHARED_SECRET) console.warn("Missing BILLING_WEBHOOK_SHARED_SECRET");

// Health
app.get("/", (_req, res) => res.status(200).send("ok"));

// IMPORTANT: raw body required for Stripe signature verification
app.post("/stripe-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const reqId = `req_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  console.log(`[${reqId}] 🔥 Stripe webhook received`);

  try {
    const sig = req.headers["stripe-signature"];
    if (!sig) {
      console.warn(`[${reqId}] Missing Stripe-Signature header`);
      return res.status(400).send("Missing Stripe-Signature header");
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error(
        `[${reqId}] Stripe signature verification failed:`,
        err?.message || err
      );
      return res.status(400).send("Bad signature");
    }

    if (!allowedTypes.has(event.type)) {
      console.log(`[${reqId}] Ignored event type: ${event.type}`);
      return res.status(200).send("Ignored");
    }

    if (!APPS_SCRIPT_WEBHOOK_URL || !BILLING_WEBHOOK_SHARED_SECRET) {
      console.error(
        `[${reqId}] Server misconfigured: missing APPS_SCRIPT_WEBHOOK_URL or BILLING_WEBHOOK_SHARED_SECRET`
      );
      return res.status(500).send("Server misconfigured");
    }

    const simplified = simplifyStripeEvent_(event);

    const forwardBody = {
      sharedSecret: BILLING_WEBHOOK_SHARED_SECRET,
      eventId: event.id,
      type: event.type,
      data: simplified,
    };

    console.log(
      `[${reqId}] Forwarding to Apps Script: ${APPS_SCRIPT_WEBHOOK_URL}`
    );

    const forwardResult = await postJsonPreservePostAcrossRedirects_(
      APPS_SCRIPT_WEBHOOK_URL,
      forwardBody,
      reqId
    );

    if (!forwardResult.ok) {
      // non-2xx so Stripe retries
      console.error(`[${reqId}] Forward failed:`, forwardResult);
      return res.status(502).send("Forward failed");
    }

    console.log(
      `[${reqId}] Forwarded OK: status=${forwardResult.status} finalUrl=${forwardResult.finalUrl} body=${truncate_(
        forwardResult.text,
        300
      )}`
    );

    // IMPORTANT: return 2xx quickly so Stripe marks webhook delivered
    return res.status(200).send("Forwarded OK");
  } catch (err) {
    console.error(`[${reqId}] Handler error:`, err);
    return res.status(500).send("Server error");
  }
});

// ----------------------------
// Critical helper: preserve POST across Apps Script redirect
// ----------------------------
async function postJsonPreservePostAcrossRedirects_(url, obj, reqId) {
  const body = JSON.stringify(obj);
  const headers = { "Content-Type": "application/json" };

  let currentUrl = url;
  let lastStatus = 0;
  let lastText = "";
  let hops = 0;

  while (hops < 5) {
    const resp = await fetch(currentUrl, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
    });

    lastStatus = resp.status;
    lastText = await safeText_(resp);

    // Success
    if (resp.ok) {
      return { ok: true, status: resp.status, finalUrl: currentUrl, text: lastText, hops };
    }

    // Redirect handling
    const loc = resp.headers.get("location");
    const isRedirect = [301, 302, 303, 307, 308].includes(resp.status);

    if (isRedirect && loc) {
      const nextUrl = new URL(loc, currentUrl).toString();
      console.log(`[${reqId}] Redirect hop ${hops + 1}: ${resp.status} -> ${nextUrl}`);
      currentUrl = nextUrl;
      hops += 1;
      continue;
    }

    // Non-redirect failure
    return {
      ok: false,
      status: resp.status,
      finalUrl: currentUrl,
      text: lastText,
      hops,
    };
  }

  // Too many redirects
  return {
    ok: false,
    status: lastStatus || 0,
    finalUrl: currentUrl,
    text: `Too many redirects. Last body: ${truncate_(lastText, 200)}`,
    hops,
  };
}

// ----------------------------
// Stripe event simplifier
// ----------------------------
function simplifyStripeEvent_(event) {
  const obj = event?.data?.object || {};

  if (event.type.startsWith("invoice.")) {
    const created = obj.created ? new Date(obj.created * 1000).toISOString() : "";
    const paidAtUnix = obj?.status_transitions?.paid_at ?? null;
    const paidAt = paidAtUnix ? new Date(paidAtUnix * 1000).toISOString() : "";

    return {
      invoiceId: obj.id || "",
      status: obj.status || "",
      hostedInvoiceUrl: obj.hosted_invoice_url || "",
      amountDue: obj.amount_due != null ? Number(obj.amount_due) / 100 : null, // dollars
      currency: obj.currency || "usd",
      createdAt: created,
      paidAt: paidAt,
      customer: obj.customer || "",
      number: obj.number || "",
      metadata: obj.metadata || {},
    };
  }

  return {
    rawType: event.type,
    objectId: obj.id || "",
    objectType: obj.object || "",
  };
}

// ----------------------------
// Utils
// ----------------------------
async function safeText_(resp) {
  try {
    return await resp.text();
  } catch {
    return "";
  }
}

function truncate_(s, n) {
  s = String(s || "");
  return s.length > n ? s.slice(0, n) + "..." : s;
}

app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
