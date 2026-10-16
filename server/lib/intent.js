const { paymentConfig } = require("./config");

function normalize(text) {
  return String(text || "").trim().replace(/\s+/g, " ");
}

function isInjection(text) {
  return /(ignore (all |any )?(previous|security|policy)|bypass|override|increase (the )?limit|forget (the )?rules)/i.test(text);
}

function parseLocalIntent(text, products) {
  const request = normalize(text);
  if (!request) return { valid: false, reason: "Enter a purchase request." };
  if (isInjection(request)) return { valid: false, reason: "Request contains instructions that attempt to alter security controls." };
  const found = products.find((product) => request.toLowerCase().includes(product.name.toLowerCase()));
  if (!found) return { valid: false, reason: "No trusted catalogue product was identified. Choose an approved product name." };
  const quantityMatch = request.match(/(?:x|quantity\s*[:=]?|buy\s+)(\d+)/i);
  const quantity = Math.max(1, Math.min(10, Number(quantityMatch ? quantityMatch[1] : 1)));
  return {
    valid: true,
    source: "local-parser",
    productId: found.id,
    quantity,
    merchantId: found.merchantId,
    budgetConstraintCents: null,
    explanation: "Proposal parsed locally. Final authorization remains server-side."
  };
}

async function proposePurchase(text, products) {
  const config = paymentConfig();
  if (!config.aiProvider || !config.aiApiKey || !config.aiModel) {
    const error = new Error("AI provider is not configured. Configure AI_PROVIDER, AI_API_KEY, and AI_MODEL to use live AI intent extraction.");
    error.code = "AI_NOT_CONFIGURED";
    throw error;
  }
  const error = new Error("Live AI adapter is configured but no provider adapter has been enabled for this build. The request was not authorized.");
  error.code = "AI_ADAPTER_UNAVAILABLE";
  throw error;
}

module.exports = { parseLocalIntent, proposePurchase, isInjection };
