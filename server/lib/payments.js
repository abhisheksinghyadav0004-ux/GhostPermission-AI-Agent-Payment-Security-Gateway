const crypto = require("crypto");
const { paymentConfig } = require("./config");

function todayKey() { return new Date().toISOString().slice(0, 10); }
function id(prefix) { return prefix + "-" + crypto.randomBytes(5).toString("hex").toUpperCase(); }

function evaluatePurchase(store, proposal, requestId) {
  const state = store.getState();
  const config = paymentConfig();
  const existing = requestId && state.transactions.find((item) => item.requestId === requestId);
  if (existing) return { transaction: existing, reused: true };
  const product = state.catalogue.products.find((item) => item.id === proposal.productId);
  const merchant = product && state.catalogue.merchants.find((item) => item.id === product.merchantId);
  const quantity = Number(proposal.quantity || 0);
  const now = new Date().toISOString();
  const transaction = {
    id: id("TXN"), requestId: requestId || id("REQ"), createdAt: now, updatedAt: now,
    productId: proposal.productId, productName: product ? product.name : null,
    merchantId: proposal.merchantId, amountCents: product ? product.priceCents * quantity : null,
    currency: product ? product.currency : null, quantity, status: "RECEIVED", decision: null,
    reason: null, approvalId: null, paypalOrderId: null, paypalCaptureId: null,
    idempotencyKey: crypto.randomUUID(), events: []
  };
  const deny = (reason) => { transaction.status = "BLOCKED"; transaction.decision = "BLOCK"; transaction.reason = reason; };
  if (!product || !merchant || !Number.isInteger(quantity) || quantity < 1 || quantity > product.maxQuantity) deny("Product, merchant, or quantity could not be validated against the trusted catalogue.");
  else if (!merchant.allowlisted) deny("Merchant is not allowlisted by the server policy.");
  else if (transaction.amountCents > config.perTransactionLimitCents) deny("Transaction exceeds the server-controlled per-transaction spending limit.");
  else {
    const spentToday = state.transactions.filter((item) => item.createdAt.slice(0, 10) === todayKey() && ["AUTHORIZED", "AWAITING_APPROVAL", "PAYPAL_ORDER_CREATED", "CAPTURED"].includes(item.status)).reduce((sum, item) => sum + Number(item.amountCents || 0), 0);
    if (spentToday + transaction.amountCents > config.dailyLimitCents) deny("Transaction exceeds the server-controlled daily spending limit.");
    else if (transaction.amountCents >= Math.round(config.perTransactionLimitCents * 0.8) && config.approvalsRequired) {
      transaction.status = "AWAITING_APPROVAL"; transaction.decision = "REQUIRE_APPROVAL"; transaction.reason = "High-value transaction requires server-managed human approval.";
    } else { transaction.status = "AUTHORIZED"; transaction.decision = "ALLOW"; transaction.reason = "Trusted catalogue and spending policies allow this transaction."; }
  }
  transaction.events.push({ timestamp: now, type: "policy.evaluated", status: transaction.status, reason: transaction.reason });
  store.addTransaction(transaction);
  return { transaction, reused: false };
}

function approveTransaction(store, transactionId, actor, decision) {
  const transaction = store.getState().transactions.find((item) => item.id === transactionId);
  if (!transaction) return null;
  if (transaction.status !== "AWAITING_APPROVAL") throw new Error("Transaction is not awaiting approval.");
  transaction.updatedAt = new Date().toISOString();
  transaction.approvalId = id("APR");
  if (decision === "APPROVE") { transaction.status = "AUTHORIZED"; transaction.decision = "ALLOW"; transaction.reason = "Human approval verified on the server."; }
  else { transaction.status = "BLOCKED"; transaction.decision = "BLOCK"; transaction.reason = "Human approver rejected this transaction."; }
  transaction.events.push({ timestamp: transaction.updatedAt, type: "approval." + decision.toLowerCase(), actor, status: transaction.status });
  store.addAudit("payment.approval." + decision.toLowerCase(), transaction.id, { actor, approvalId: transaction.approvalId, status: transaction.status });
  store.save();
  return transaction;
}

module.exports = { evaluatePurchase, approveTransaction };
