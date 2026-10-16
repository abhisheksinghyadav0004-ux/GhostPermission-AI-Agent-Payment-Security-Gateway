const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const defaultFile = path.join(__dirname, "..", "..", "data", "ghostpermission-db.json");
const tools = ["read_document", "summarize", "redact", "send_internal", "send_external"];
const classifications = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];
const trustLevels = ["APPROVED_INTERNAL", "APPROVED_EXTERNAL", "EXTERNAL_REVIEW_REQUIRED", "PROHIBITED_EXTERNAL", "UNKNOWN"];const legacySampleMerchantIds = new Set(["merchant-security-store", "merchant-office-supply"]);const legacySampleProductIds = new Set(["product-usb-security-key", "product-privacy-screen"]);

function now() {
  return new Date().toISOString();
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function makeId(prefix, name = "") {
  const slug = String(name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 38);
  return prefix + "-" + (slug || crypto.randomBytes(4).toString("hex"));
}

function seed() {
  return {
    meta: { product: "GhostPermission", createdAt: now(), workspaceMode: "real-local" },
    agents: [],
    resources: [],
    destinations: [],
    policies: [
      { id: "POL-RESTRICTED-PROHIBITED", name: "Restricted data cannot leave to prohibited external destinations", enabled: true, severity: "CRITICAL" },
      { id: "POL-CONFIDENTIAL-APPROVAL", name: "Confidential outbound transfer requires approval or redaction", enabled: true, severity: "HIGH" },
      { id: "POL-UNKNOWN-DESTINATION", name: "Sensitive data cannot be sent to unknown destinations", enabled: true, severity: "HIGH" },
      { id: "POL-TOOL-PERMISSION", name: "Agents may only invoke assigned tools", enabled: true, severity: "HIGH" }
    ],    catalogue: { merchants: [], products: [] },    transactions: [],
    workflows: [],
    actions: [],
    incidents: [],
    audit: [],    exports: []
  };
}

function normalizeState(state) {
  const fresh = seed();  const incomingCatalogue = state.catalogue && Array.isArray(state.catalogue.products) && Array.isArray(state.catalogue.merchants) ? state.catalogue : fresh.catalogue;  const merchants = incomingCatalogue.merchants.filter((merchant) => !legacySampleMerchantIds.has(merchant.id));  const products = incomingCatalogue.products.filter((product) => !legacySampleProductIds.has(product.id) && !legacySampleMerchantIds.has(product.merchantId));  const transactions = Array.isArray(state.transactions) ? state.transactions.filter((transaction) => !legacySampleMerchantIds.has(transaction.merchantId) && !legacySampleProductIds.has(transaction.productId)) : [];
  return {
    ...fresh,
    ...state,
    meta: { ...fresh.meta, ...(state.meta || {}), workspaceMode: "real-local" },
    agents: Array.isArray(state.agents) ? state.agents : [],
    resources: Array.isArray(state.resources) ? state.resources : [],
    destinations: Array.isArray(state.destinations) ? state.destinations : [],    catalogue: { merchants, products },    transactions,
    policies: Array.isArray(state.policies) && state.policies.length ? state.policies : fresh.policies,
    workflows: Array.isArray(state.workflows) ? state.workflows : [],
    actions: Array.isArray(state.actions) ? state.actions : [],
    incidents: Array.isArray(state.incidents) ? state.incidents : [],
    audit: Array.isArray(state.audit) ? state.audit : [],    exports: Array.isArray(state.exports) ? state.exports : []
  };
}

class Store {
  constructor(file = process.env.GHOSTPERMISSION_DATA_FILE || defaultFile) {
    this.file = path.resolve(file);
    this.state = null;
  }

  load() {
    if (!fs.existsSync(this.file)) {
      this.state = seed();
      this.save();
      return this.state;
    }
    this.state = normalizeState(JSON.parse(fs.readFileSync(this.file, "utf8")));    this.save();
    return this.state;
  }

  getState() {
    if (!this.state) this.load();
    return this.state;
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.state, null, 2), "utf8");
  }

  reset() {
    this.state = seed();
    this.save();
    return this.getPublicState();
  }

  getPublicState() {
    const state = clone(this.getState());
    state.catalog = { tools, classifications, trustLevels };
    state.metrics = {
      totalActions: state.actions.length,
      allowed: state.actions.filter((a) => a.decision === "ALLOW").length,
      blocked: state.actions.filter((a) => a.decision === "BLOCK").length,
      review: state.actions.filter((a) => a.decision === "REQUIRE_APPROVAL").length,
      activePolicies: state.policies.filter((p) => p.enabled).length,
      incidents: state.incidents.length,
      sensitiveTransfers: state.actions.filter((a) => ["CONFIDENTIAL", "RESTRICTED"].includes(a.classification)).length,
      sequenceViolations: state.actions.filter((a) => a.sequenceViolation).length
    };    state.metrics.paymentTransactions = state.transactions.length;    state.metrics.pendingApprovals = state.transactions.filter((transaction) => transaction.status === "AWAITING_APPROVAL").length;    state.metrics.capturedPayments = state.transactions.filter((transaction) => transaction.status === "CAPTURED").length;    state.analytics = this.buildAnalytics(state);
    return state;
  }  buildAnalytics(state) {    const countBy = (items, getKey) => items.reduce((acc, item) => {      const key = getKey(item) || "UNKNOWN";      acc[key] = (acc[key] || 0) + 1;      return acc;    }, {});    const riskBuckets = { "0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0 };    for (const action of state.actions) {      if (action.riskScore <= 25) riskBuckets["0-25"] += 1;      else if (action.riskScore <= 50) riskBuckets["26-50"] += 1;      else if (action.riskScore <= 75) riskBuckets["51-75"] += 1;      else riskBuckets["76-100"] += 1;    }    return {      decisions: countBy(state.actions, (action) => action.decision),      policyTriggers: countBy(state.actions.flatMap((action) => action.matchedPolicies || []), (policyId) => policyId),      agentActivity: countBy(state.actions, (action) => action.agentId),      destinationViolations: countBy(state.actions.filter((action) => action.destinationId && action.decision !== "ALLOW"), (action) => action.destinationId),      riskBuckets    };  }

  createAgent(input) {
    const name = String(input.name || "").trim();
    const allowedTools = Array.isArray(input.allowedTools) ? input.allowedTools.filter((tool) => tools.includes(tool)) : [];
    if (!name) throw new Error("Agent name is required");
    if (!allowedTools.length) throw new Error("Select at least one allowed tool");
    const agent = { id: makeId("agent", name), name, allowedTools, createdAt: now() };
    this.getState().agents.push(agent);
    this.addAudit("agent.created", agent.id, { name: agent.name, allowedTools });
    this.save();
    return agent;
  }  addTransaction(transaction) {    this.getState().transactions.unshift(transaction);    this.addAudit("payment.request.received", transaction.id, {      requestId: transaction.requestId,      decision: transaction.decision,      status: transaction.status,      amountCents: transaction.amountCents,      currency: transaction.currency    });    if (transaction.status === "BLOCKED") this.addIncident({      id: transaction.id,      agentId: "payment-request",      workflowId: null,      matchedPolicies: ["PAYMENT-POLICY"],      classification: "PAYMENT",      destinationId: transaction.merchantId,      explanation: transaction.reason,      riskScore: 90    });    this.save();    return transaction;  }

  createResource(input) {
    const name = String(input.name || "").trim();
    const owner = String(input.owner || "").trim();
    const classification = String(input.classification || "").trim();
    if (!name) throw new Error("Resource name is required");
    if (!owner) throw new Error("Resource owner is required");
    if (!classifications.includes(classification)) throw new Error("Invalid classification");
    const resource = { id: makeId("resource", name), name, owner, classification, createdAt: now() };
    this.getState().resources.push(resource);
    this.addAudit("resource.created", resource.id, { name: resource.name, classification });
    this.save();
    return resource;
  }

  createDestination(input) {
    const name = String(input.name || "").trim();
    const trust = String(input.trust || "").trim();
    if (!name) throw new Error("Destination name is required");
    if (!trustLevels.includes(trust)) throw new Error("Invalid destination trust level");
    const destination = { id: makeId("destination", name), name, trust, createdAt: now() };
    this.getState().destinations.push(destination);
    this.addAudit("destination.created", destination.id, { name: destination.name, trust });
    this.save();
    return destination;
  }  createMerchant(input) {    const name = String(input.name || "").trim();    if (!name) throw new Error("Merchant name is required");    const merchant = { id: makeId("merchant", name), name, allowlisted: input.allowlisted === true, createdAt: now() };    this.getState().catalogue.merchants.push(merchant);    this.addAudit("merchant.created", merchant.id, { name: merchant.name, allowlisted: merchant.allowlisted });    this.save();    return merchant;  }  createProduct(input) {    const name = String(input.name || "").trim();    const merchantId = String(input.merchantId || "").trim();    const priceCents = Number(input.priceCents);    const currency = String(input.currency || "USD").trim().toUpperCase();    const maxQuantity = Number(input.maxQuantity);    const merchant = this.getState().catalogue.merchants.find((item) => item.id === merchantId && item.allowlisted);    if (!name || !merchant) throw new Error("Choose an allowlisted merchant and enter a product name");    if (!Number.isInteger(priceCents) || priceCents < 1) throw new Error("Price must be a positive whole number of cents");    if (!/^[A-Z]{3}$/.test(currency)) throw new Error("Currency must be a three-letter ISO code");    if (!Number.isInteger(maxQuantity) || maxQuantity < 1 || maxQuantity > 100) throw new Error("Maximum quantity must be between 1 and 100");    const product = { id: makeId("product", name), name, merchantId, priceCents, currency, maxQuantity, createdAt: now() };    this.getState().catalogue.products.push(product);    this.addAudit("product.created", product.id, { name: product.name, merchantId, priceCents, currency, maxQuantity });    this.save();    return product;  }

  updatePolicy(id, patch) {
    const policy = this.getState().policies.find((item) => item.id === id);
    if (!policy) return null;
    Object.assign(policy, patch);
    this.addAudit("policy.updated", id, { patch });
    this.save();
    return policy;
  }

  updateIncident(id, patch) {    const incident = this.getState().incidents.find((item) => item.id === id);    if (!incident) return null;    const allowed = {};    if (patch.status) allowed.status = patch.status;    if (patch.note) {      incident.notes = Array.isArray(incident.notes) ? incident.notes : [];      incident.notes.push({ id: "NOTE-" + crypto.randomBytes(3).toString("hex").toUpperCase(), timestamp: now(), actor: "analyst", body: String(patch.note).trim() });    }    Object.assign(incident, allowed, { updatedAt: now() });    this.addAudit("incident.updated", id, { patch: allowed, noteAdded: Boolean(patch.note) });    this.save();    return incident;  }  exportIncident(id) {    const incident = this.getState().incidents.find((item) => item.id === id);    if (!incident) return null;    const relatedAction = this.getState().actions.find((action) => action.id === incident.actionId) || null;    const report = { exportedAt: now(), incident, relatedAction, auditVerification: this.verifyAudit() };    this.addAudit("incident.exported", id, { format: "json" });    this.save();    return report;  }  exportAudit() {    const report = { exportedAt: now(), verification: this.verifyAudit(), audit: this.getState().audit };    this.addAudit("audit.exported", "audit-log", { records: this.getState().audit.length });    this.save();    return report;  }

  addAction(action) {
    if (action.requestId) {      const existing = this.getState().actions.find((item) => item.requestId === action.requestId);      if (existing) return existing;    }    this.getState().actions.unshift(action);
    this.addAudit("action.evaluated", action.id, { decision: action.decision, downstreamExecution: action.downstreamExecution });
    if (action.decision === "BLOCK" && action.riskScore >= 80) {
      this.addIncident(action);
    }
    this.save();    return action;
  }

  addWorkflow(workflow) {
    this.getState().workflows.unshift(workflow);
    this.addAudit("workflow.completed", workflow.id, { actions: workflow.actionIds.length });
    this.save();
  }

  addIncident(action) {
    const exists = this.getState().incidents.some((item) => item.actionId === action.id);
    if (exists) return;
    this.getState().incidents.unshift({
      id: "INC-" + crypto.randomBytes(4).toString("hex").toUpperCase(),
      actionId: action.id,
      title: "Blocked outbound authorization request",
      severity: "CRITICAL",
      status: "OPEN",
      summary: action.explanation,      relatedAgent: action.agentId,      workflowId: action.workflowId,      triggeredPolicy: (action.matchedPolicies || [])[0] || "POLICY",      classification: action.classification,      destinationId: action.destinationId,      evidenceActionId: action.id,      notes: [],
      createdAt: now(),
      updatedAt: now()
    });
  }

  addAudit(type, target, details = {}) {
    const state = this.getState();
    const previousHash = state.audit[0] ? state.audit[0].hash : "GENESIS";
    const record = {
      id: "AUD-" + crypto.randomBytes(4).toString("hex").toUpperCase(),
      timestamp: now(),
      actor: "system",
      type,
      target,
      details,
      previousHash
    };
    record.hash = this.hashRecord(record);
    state.audit.unshift(record);
    return record;
  }

  hashRecord(record) {
    const input = JSON.stringify({
      id: record.id,
      timestamp: record.timestamp,
      actor: record.actor,
      type: record.type,
      target: record.target,
      details: record.details,
      previousHash: record.previousHash
    });
    return crypto.createHash("sha256").update(input).digest("hex");
  }

  verifyAudit() {
    const audit = this.getState().audit;
    const failures = [];
    for (let i = 0; i < audit.length; i += 1) {
      const record = audit[i];
      const expectedHash = this.hashRecord(record);
      const expectedPrevious = audit[i + 1] ? audit[i + 1].hash : "GENESIS";
      if (record.hash !== expectedHash) failures.push({ id: record.id, reason: "hash mismatch" });
      if (record.previousHash !== expectedPrevious) failures.push({ id: record.id, reason: "previous hash mismatch" });
    }
    return { valid: failures.length === 0, checkedRecords: audit.length, failures };
  }
}

module.exports = { Store, seed, tools, classifications, trustLevels };
