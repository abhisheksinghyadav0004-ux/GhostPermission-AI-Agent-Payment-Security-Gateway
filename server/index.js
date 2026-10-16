const http = require("http");const { loadLocalEnv } = require("./lib/env");loadLocalEnv();
const fs = require("fs");
const path = require("path");
const { Store } = require("./lib/store");
const { evaluateAction, runWorkflow } = require("./lib/engine");const { parseLocalIntent, proposePurchase } = require("./lib/intent");const { evaluatePurchase, approveTransaction } = require("./lib/payments");const { publicIntegrationStatus } = require("./lib/config");const paypal = require("./lib/paypal");

const port = Number(process.env.PORT || 5173);
const publicDir = path.join(__dirname, "..", "public");
const store = new Store();
store.load();

function send(res, status, payload, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Access-Control-Allow-Origin": process.env.ALLOWED_ORIGIN || "http://127.0.0.1:" + port,
    "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Approval-Token, X-Admin-Token"
  });
  res.end(type === "application/json" ? JSON.stringify(payload, null, 2) : payload);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
  });
}

function staticFile(req, res) {
  const clean = req.url.split("?")[0] === "/" ? "/index.html" : req.url.split("?")[0];
  const file = path.normalize(path.join(publicDir, clean));
  if (!file.startsWith(publicDir)) return send(res, 403, "Forbidden", "text/plain");
  if (!fs.existsSync(file)) return send(res, 404, "Not found", "text/plain");
  const ext = path.extname(file);
  const types = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json" };
  send(res, 200, fs.readFileSync(file), types[ext] || "text/plain");
}function approvalActor(req) {  const expected = process.env.LOCAL_APPROVER_TOKEN || "";  const supplied = String(req.headers["x-approval-token"] || "");  if (!expected || supplied !== expected) return null;  return "local-approver";}function adminActor(req) {  const expected = process.env.LOCAL_ADMIN_TOKEN || "";  const supplied = String(req.headers["x-admin-token"] || "");  if (!expected || supplied !== expected) return null;  return "local-admin";}function transactionById(transactionId) {  return store.getState().transactions.find((transaction) => transaction.id === transactionId) || null;}

async function router(req, res) {
  if (req.method === "OPTIONS") return send(res, 204, {});
  const url = new URL(req.url, "http://localhost");

  try {
    if (url.pathname === "/api/health" && req.method === "GET") {
      return send(res, 200, { ok: true, product: "GhostPermission", mode: "payment-authorization", integrations: publicIntegrationStatus() });
    }
    if (url.pathname === "/api/state" && req.method === "GET") {
      return send(res, 200, store.getPublicState());
    }    if (url.pathname === "/api/integrations/status" && req.method === "GET") {      return send(res, 200, publicIntegrationStatus());    }    if (url.pathname === "/api/purchases/intent" && req.method === "POST") {      const body = await parseBody(req);      const text = String(body.text || "");      if (body.mode === "live-ai") {        const proposal = await proposePurchase(text, store.getState().catalogue.products);        return send(res, 200, { proposal });      }      const proposal = parseLocalIntent(text, store.getState().catalogue.products);      store.addAudit(proposal.valid ? "payment.intent.parsed" : "payment.intent.rejected", "purchase-intent", { source: proposal.source || "local-parser", reason: proposal.reason || null });      store.save();      return send(res, proposal.valid ? 200 : 400, { proposal });    }    if (url.pathname === "/api/purchases/authorize" && req.method === "POST") {      const body = await parseBody(req);      const proposal = body.proposal;      if (!proposal || !proposal.productId || !proposal.merchantId) return send(res, 400, { error: "Validated purchase proposal is required." });      const result = evaluatePurchase(store, proposal, body.requestId);      return send(res, 200, { ...result, state: store.getPublicState() });    }    if (url.pathname === "/api/transactions" && req.method === "GET") {      return send(res, 200, { transactions: store.getState().transactions, integrations: publicIntegrationStatus() });    }    const approvalMatch = url.pathname.match(/^\/api\/transactions\/([^/]+)\/approval$/);    if (approvalMatch && req.method === "POST") {      const actor = approvalActor(req);      if (!actor) return send(res, 403, { error: "Approver token is required. Configure LOCAL_APPROVER_TOKEN and provide it in X-Approval-Token." });      const body = await parseBody(req);      if (!["APPROVE", "REJECT"].includes(body.decision)) return send(res, 400, { error: "decision must be APPROVE or REJECT" });      const transaction = approveTransaction(store, approvalMatch[1], actor, body.decision);      return transaction ? send(res, 200, { transaction, state: store.getPublicState() }) : send(res, 404, { error: "Transaction not found" });    }    const paypalOrderMatch = url.pathname.match(/^\/api\/transactions\/([^/]+)\/paypal-order$/);    if (paypalOrderMatch && req.method === "POST") {      const transaction = transactionById(paypalOrderMatch[1]);      if (!transaction) return send(res, 404, { error: "Transaction not found" });      if (!["AUTHORIZED", "PAYPAL_CONFIGURATION_REQUIRED", "PAYPAL_ORDER_FAILED"].includes(transaction.status)) return send(res, 409, { error: "Only server-authorized transactions can create a PayPal order." });      try {        const order = await paypal.createOrder(transaction);        if (!order.id || order.status !== "CREATED") throw new Error("PayPal did not return a valid CREATED order.");        transaction.paypalOrderId = order.id;        transaction.status = "PAYPAL_ORDER_CREATED";        transaction.updatedAt = new Date().toISOString();        transaction.events.push({ timestamp: transaction.updatedAt, type: "paypal.order.created", status: transaction.status });        store.addAudit("paypal.order.created", transaction.id, { paypalOrderId: order.id, status: order.status });        store.save();        return send(res, 200, { transaction, order });      } catch (error) {        transaction.status = error.code === "PAYPAL_NOT_CONFIGURED" ? "PAYPAL_CONFIGURATION_REQUIRED" : "PAYPAL_ORDER_FAILED";        transaction.updatedAt = new Date().toISOString();        transaction.events.push({ timestamp: transaction.updatedAt, type: "paypal.order.failed", status: transaction.status, reason: error.message });        store.addAudit("paypal.order.failed", transaction.id, { code: error.code || "UNKNOWN", reason: error.message });        store.save();        return send(res, error.code === "PAYPAL_NOT_CONFIGURED" ? 503 : 502, { error: error.message, transaction });      }    }    const captureMatch = url.pathname.match(/^\/api\/transactions\/([^/]+)\/capture$/);    if (captureMatch && req.method === "POST") {      const transaction = transactionById(captureMatch[1]);      if (!transaction) return send(res, 404, { error: "Transaction not found" });      if (transaction.status !== "PAYPAL_ORDER_CREATED" || !transaction.paypalOrderId) return send(res, 409, { error: "Transaction is not ready for capture." });      try {        const order = await paypal.getOrder(transaction.paypalOrderId);        if (order.status !== "APPROVED") return send(res, 409, { error: "PayPal order has not been approved by the buyer.", transaction, paypalStatus: order.status });        const capture = await paypal.captureOrder(transaction.paypalOrderId, transaction.idempotencyKey + "-capture");        if (capture.status !== "COMPLETED") throw new Error("PayPal capture did not reach COMPLETED status.");        const captureData = capture.purchase_units && capture.purchase_units[0] && capture.purchase_units[0].payments && capture.purchase_units[0].payments.captures && capture.purchase_units[0].payments.captures[0];        if (!captureData || captureData.amount.currency_code !== transaction.currency || captureData.amount.value !== (transaction.amountCents / 100).toFixed(2)) throw new Error("PayPal capture amount or currency did not match the server transaction.");        transaction.paypalCaptureId = captureData.id;        transaction.status = "CAPTURED";        transaction.updatedAt = new Date().toISOString();        transaction.events.push({ timestamp: transaction.updatedAt, type: "paypal.capture.verified", status: transaction.status });        store.addAudit("paypal.capture.verified", transaction.id, { paypalOrderId: transaction.paypalOrderId, paypalCaptureId: transaction.paypalCaptureId });        store.save();        return send(res, 200, { transaction, capture });      } catch (error) {        transaction.status = "PAYPAL_CAPTURE_FAILED";        transaction.updatedAt = new Date().toISOString();        transaction.events.push({ timestamp: transaction.updatedAt, type: "paypal.capture.failed", status: transaction.status, reason: error.message });        store.addAudit("paypal.capture.failed", transaction.id, { reason: error.message });        store.save();        return send(res, 502, { error: error.message, transaction });      }    }
    if (url.pathname === "/api/audit/verify" && req.method === "GET") {
      return send(res, 200, store.verifyAudit());
    }    if (url.pathname === "/api/audit/export" && req.method === "GET") {      return send(res, 200, store.exportAudit());    }
    if (url.pathname === "/api/reset" && req.method === "POST") {
      if (!adminActor(req)) return send(res, 403, { error: "Admin token is required. Configure LOCAL_ADMIN_TOKEN and provide it in X-Admin-Token." });      return send(res, 200, store.reset());
    }
    if (url.pathname === "/api/agents" && req.method === "POST") {
      const agent = store.createAgent(await parseBody(req));
      return send(res, 201, { agent, state: store.getPublicState() });
    }
    if (url.pathname === "/api/resources" && req.method === "POST") {
      const resource = store.createResource(await parseBody(req));
      return send(res, 201, { resource, state: store.getPublicState() });
    }
    if (url.pathname === "/api/destinations" && req.method === "POST") {
      const destination = store.createDestination(await parseBody(req));
      return send(res, 201, { destination, state: store.getPublicState() });
    }    if (url.pathname === "/api/merchants" && req.method === "POST") {      const merchant = store.createMerchant(await parseBody(req));      return send(res, 201, { merchant, state: store.getPublicState() });    }    if (url.pathname === "/api/products" && req.method === "POST") {      const product = store.createProduct(await parseBody(req));      return send(res, 201, { product, state: store.getPublicState() });    }
    if (url.pathname === "/api/actions/evaluate" && req.method === "POST") {
      const body = await parseBody(req);
      const action = evaluateAction(store, body);
      return send(res, 200, { action, state: store.getPublicState() });
    }    if (url.pathname === "/api/workflows/run" && req.method === "POST") {      const body = await parseBody(req);      if (!Array.isArray(body.steps) || body.steps.length === 0) return send(res, 400, { error: "steps must contain at least one action" });      const result = runWorkflow(store, body.name, body.steps);      return send(res, 200, { ...result, state: store.getPublicState() });    }
    const policyMatch = url.pathname.match(/^\/api\/policies\/([^/]+)$/);
    if (policyMatch && req.method === "PATCH") {
      if (!adminActor(req)) return send(res, 403, { error: "Admin token is required to modify policy state." });      const body = await parseBody(req);
      const policy = store.updatePolicy(policyMatch[1], body);
      return policy ? send(res, 200, { policy, state: store.getPublicState() }) : send(res, 404, { error: "Policy not found" });
    }
    const incidentExportMatch = url.pathname.match(/^\/api\/incidents\/([^/]+)\/export$/);
    if (incidentExportMatch && req.method === "GET") {
      const report = store.exportIncident(incidentExportMatch[1]);
      return report ? send(res, 200, report) : send(res, 404, { error: "Incident not found" });
    }
    const incidentMatch = url.pathname.match(/^\/api\/incidents\/([^/]+)$/);
    if (incidentMatch && req.method === "PATCH") {
      const body = await parseBody(req);
      const incident = store.updateIncident(incidentMatch[1], body);
      return incident ? send(res, 200, { incident, state: store.getPublicState() }) : send(res, 404, { error: "Incident not found" });
    }
    if (url.pathname.startsWith("/api/")) return send(res, 404, { error: "API route not found" });
    return staticFile(req, res);
  } catch (error) {
    return send(res, 400, { error: error.message });
  }
}

const server = http.createServer(router);
server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error("Port " + port + " is already in use. Stop the existing server or run with another PORT value.");
    process.exit(1);
  }
  throw error;
});
server.listen(port, "127.0.0.1", () => {
  console.log("GhostPermission running at http://127.0.0.1:" + port);
});
