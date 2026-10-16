const crypto = require("crypto");
const { paymentConfig } = require("./config");

let tokenCache = null;

function configured() {
  const config = paymentConfig();
  return Boolean(config.paypalClientId && config.paypalClientSecret);
}

async function paypalFetch(path, options = {}) {
  const config = paymentConfig();
  if (!configured()) {
    const error = new Error("PayPal Sandbox is not configured. Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET on the server.");
    error.code = "PAYPAL_NOT_CONFIGURED";
    throw error;
  }
  const response = await fetch(config.paypalBaseUrl + path, options);
  const text = await response.text();
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text }; }
  if (!response.ok) {
    const error = new Error(body.message || "PayPal Sandbox request failed");
    error.code = "PAYPAL_API_ERROR";
    error.status = response.status;
    error.details = body;
    throw error;
  }
  return body;
}

async function accessToken() {
  if (tokenCache && tokenCache.expiresAt > Date.now() + 30000) return tokenCache.value;
  const config = paymentConfig();
  const basic = Buffer.from(config.paypalClientId + ":" + config.paypalClientSecret).toString("base64");
  const result = await paypalFetch("/v1/oauth2/token", {
    method: "POST",
    headers: { Authorization: "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials"
  });
  tokenCache = { value: result.access_token, expiresAt: Date.now() + Number(result.expires_in || 300) * 1000 };
  return tokenCache.value;
}

async function createOrder(transaction) {
  const token = await accessToken();
  return paypalFetch("/v2/checkout/orders", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      "PayPal-Request-Id": transaction.idempotencyKey
    },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [{
        reference_id: transaction.id,
        description: transaction.productName,
        amount: { currency_code: transaction.currency, value: (transaction.amountCents / 100).toFixed(2) }
      }]
    })
  });
}

async function getOrder(orderId) {
  const token = await accessToken();
  return paypalFetch("/v2/checkout/orders/" + encodeURIComponent(orderId), { headers: { Authorization: "Bearer " + token } });
}

async function captureOrder(orderId, idempotencyKey = crypto.randomUUID()) {
  const token = await accessToken();
  return paypalFetch("/v2/checkout/orders/" + encodeURIComponent(orderId) + "/capture", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json", "PayPal-Request-Id": idempotencyKey }
  });
}

module.exports = { configured, createOrder, getOrder, captureOrder };
