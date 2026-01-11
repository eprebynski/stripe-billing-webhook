// deploy trigger
const express = require("express");
const Stripe = require("stripe");

const app = express();

// ---- Config ----
const PORT = process.env.PORT || 8080;

const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || "").trim();
const APPS_SCRIPT_WEBHOOK_URL = (process.env.APPS_SCRIPT_WEBHOOK_URL || "").trim();
const BILLING_WEBHOOK_SHARED_SECRET = (process.env.BILLING_WEBHOOK_SHARED_SECRET || "").trim();

const allowedTypes = new Set(
  (process.env.ALLOWED_EVENT_TYPES || "invoice.paid,invoice.payment_failed,invoice.finalized")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);

// Stripe lib needs *some* key string; not used for webhook verification.
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_placeholder");

// ---- Health ----
app.get("/", (_req, res) => res.status(200).send("ok"));

// ---- Stripe webhook (RAW body required) ----
app.post("/stripe-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const sig = req.headers["stripe-signature"];
    if (!sig) return res.status(400).send("Missing Stripe-Signature header");
    if (!STRIPE_WEBHOOK_SECRET) return res.status(500).send("Missing STRIPE_WEBHOOK_SECRET");

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error("Bad signature:", err && err.message ? err.message : err);
      return res.status(400).send("Bad signature");
    }

    if (!allowedTypes.has(event.type)) {
      return res.status(200).send("Ignored event type");
    }

    if (!APPS_SCRIPT_WEBHOOK_URL || !BILLING_WEBHOOK_SHARED_SECRET) {
      console.error("Missing APPS_SCRIPT_WEBHOOK_URL or BILLING_WEBHOOK_SHARED_SECRET");
      return res.status(500).send("Server misconfigured");
    }

    const simplified = simplifyStripeEvent(event);

    const forwardBody = {
      sharedSecret: BILLING_WEBHOOK_SHARED_SECRET,
      eventId: event.id,
      type: event.type,
      data: simplified,
    };

    const resp = await fetch(APPS_SCRIPT_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(forwardBody),
      redirect: "follow",
    });

    const text = await resp.text();
    if (!resp.ok) {
      console.error("Apps Script forward failed:", resp.status, text);
      return res.status(502).send("Forward failed");
    }

    return res.status(200).send("Forwarded OK");
  } catch (err) {
    console.error("Webhook handler error:", err);
    return res.status(500).send("Server error");
  }
});

function simplifyStripeEvent(event) {
  const obj = (event && event.data && event.data.object) ? event.data.object : {};

  if (String(event.type || "").startsWith("invoice.")) {
    const createdAt = obj.created ? new Date(obj.created * 1000).toISOString() : "";
    const paidUnix = obj?.status_transitions?.paid_at != null ? obj.status_transitions.paid_at : null;
    const paidAt = paidUnix ? new Date(paidUnix * 1000).toISOString() : "";

    return {
      invoiceId: obj.id || "",
      status: obj.status || "",
      hostedInvoiceUrl: obj.hosted_invoice_url || "",
      amountDue: obj.amount_due != null ? Number(obj.amount_due) / 100 : null,
      currency: obj.currency || "usd",
      createdAt,
      paidAt,
      metadata: obj.metadata || {},
      customer: obj.customer || "",
      number: obj.number || "",
    };
  }

  return { objectId: obj.id || "", objectType: obj.object || "", rawType: event.type };
}

app.listen(PORT, () => console.log(`Listening on ${PORT}`));

