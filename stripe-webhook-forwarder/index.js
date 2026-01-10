// index.js
// Cloud Run Stripe webhook → verifies Stripe signature → forwards simplified event to Apps Script
//
// Env vars required:
//   STRIPE_WEBHOOK_SECRET         = whsec_...   (from Stripe webhook endpoint details)
//   APPS_SCRIPT_WEBHOOK_URL       = https://script.google.com/macros/s/.../exec?mode=billingWebhook
//   BILLING_WEBHOOK_SHARED_SECRET = whsec_...   (your Apps Script shared secret, NOT Stripe's)
// Optional:
//   ALLOWED_EVENT_TYPES           = invoice.paid,invoice.payment_failed,invoice.finalized
//
// Deploy notes:
// - Stripe signature verification REQUIRES the raw request body.
// - This app uses express.raw({type:'application/json'}) for /stripe-webhook.

import express from "express";
import Stripe from "stripe";

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 8080;

const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || "").trim();
const APPS_SCRIPT_WEBHOOK_URL = (process.env.APPS_SCRIPT_WEBHOOK_URL || "").trim();
const BILLING_WEBHOOK_SHARED_SECRET = (process.env.BILLING_WEBHOOK_SHARED_SECRET || "").trim();

const allowedTypes = new Set(
  (process.env.ALLOWED_EVENT_TYPES || "invoice.paid,invoice.payment_failed,invoice.finalized")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

if (!STRIPE_WEBHOOK_SECRET) console.warn("Missing STRIPE_WEBHOOK_SECRET");
if (!APPS_SCRIPT_WEBHOOK_URL) console.warn("Missing APPS_SCRIPT_WEBHOOK_URL");
if (!BILLING_WEBHOOK_SHARED_SECRET) console.warn("Missing BILLING_WEBHOOK_SHARED_SECRET");

// Use Stripe API version default (fine for webhook verification)
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_placeholder", {
  apiVersion: "2024-06-20", // safe pinned version; change if you prefer
});

// ---------- Health ----------
app.get("/", (_req, res) => {
  res.status(200).send("ok");
});

// ---------- Stripe webhook endpoint (raw body required) ----------
app.post(
  "/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const sig = req.headers["stripe-signature"];
      if (!sig) return res.status(400).send("Missing Stripe-Signature header");

      // Verify signature using RAW body buffer
      let event;
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
      } catch (err) {
        console.error("Stripe signature verification failed:", err?.message || err);
        return res.status(400).send("Bad signature");
      }

      // Ignore unneeded event types
      if (!allowedTypes.has(event.type)) {
        return res.status(200).send("Ignored event type");
      }

      // Build a simplified payload for Apps Script
      const simplified = simplifyStripeEvent(event);

      // Forward to Apps Script
      if (!APPS_SCRIPT_WEBHOOK_URL || !BILLING_WEBHOOK_SHARED_SECRET) {
        console.error("Missing APPS_SCRIPT_WEBHOOK_URL or BILLING_WEBHOOK_SHARED_SECRET");
        return res.status(500).send("Server misconfigured");
      }

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

      // IMPORTANT: Return 2xx quickly so Stripe marks webhook delivered
      return res.status(200).send("Forwarded OK");
    } catch (err) {
      console.error("Webhook handler error:", err);
      return res.status(500).send("Server error");
    }
  }
);

// ---------- Helpers ----------
function simplifyStripeEvent(event) {
  // Stripe event payload lives at event.data.object
  const obj = event?.data?.object || {};

  // Handle invoice.* primarily
  if (event.type.startsWith("invoice.")) {
    // Stripe stores timestamps as unix seconds
    const created = obj.created ? new Date(obj.created * 1000).toISOString() : "";
    const paidAtUnix =
      obj?.status_transitions?.paid_at != null ? obj.status_transitions.paid_at : null;
    const paidAt = paidAtUnix ? new Date(paidAtUnix * 1000).toISOString() : "";

    return {
      invoiceId: obj.id || "",
      status: obj.status || "",
      hostedInvoiceUrl: obj.hosted_invoice_url || "",
      amountDue: obj.amount_due != null ? Number(obj.amount_due) / 100 : null, // dollars
      currency: obj.currency || "usd",
      createdAt: created,
      paidAt: paidAt,
      // metadata can be super useful for mapping back to businessId/month if you set it
      metadata: obj.metadata || {},
      customer: obj.customer || "",
      number: obj.number || "",
    };
  }

  // Fallback generic
  return {
    objectId: obj.id || "",
    objectType: obj.object || "",
    rawType: event.type,
  };
}

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
