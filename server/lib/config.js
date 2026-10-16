function bool(value) {
  return String(value || "").toLowerCase() === "true";
}

function paymentConfig() {
  const requestedBaseUrl = process.env.PAYPAL_BASE_URL || "https://api-m.sandbox.paypal.com";
  return {
    paypalClientId: process.env.PAYPAL_CLIENT_ID || "",
    paypalClientSecret: process.env.PAYPAL_CLIENT_SECRET || "",
    paypalBaseUrl: requestedBaseUrl === "https://api-m.sandbox.paypal.com" ? requestedBaseUrl : "https://api-m.sandbox.paypal.com",
    aiProvider: process.env.AI_PROVIDER || "",
    aiApiKey: process.env.AI_API_KEY || "",
    aiModel: process.env.AI_MODEL || "",
    dailyLimitCents: Number(process.env.DAILY_SPEND_LIMIT_CENTS || 10000),
    perTransactionLimitCents: Number(process.env.PER_TRANSACTION_LIMIT_CENTS || 5000),
    approvalsRequired: bool(process.env.REQUIRE_HUMAN_APPROVAL_FOR_HIGH_RISK || "true")
  };
}

function publicIntegrationStatus() {
  const config = paymentConfig();
  return {
    paypal: {
      configured: Boolean(config.paypalClientId && config.paypalClientSecret),
      mode: "sandbox",
      baseUrl: config.paypalBaseUrl
    },
    ai: {
      configured: Boolean(config.aiProvider && config.aiApiKey && config.aiModel),
      provider: config.aiProvider || "not-configured",
      model: config.aiModel || "not-configured"
    }
  };
}

module.exports = { paymentConfig, publicIntegrationStatus };
