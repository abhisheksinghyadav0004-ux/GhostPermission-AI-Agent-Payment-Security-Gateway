const crypto = require("crypto");

const sensitivityRank = { PUBLIC: 10, INTERNAL: 25, CONFIDENTIAL: 70, RESTRICTED: 95 };
const outboundTools = new Set(["send_external", "send_internal"]);

function id(prefix) {
  return prefix + "-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

function strongestClassification(resources) {
  return resources.reduce((strongest, resource) => {
    const value = sensitivityRank[resource.classification] || 0;
    const current = sensitivityRank[strongest] || 0;
    return value > current ? resource.classification : strongest;
  }, "PUBLIC");
}

function enabled(state, id) {
  const policy = state.policies.find((item) => item.id === id);
  return Boolean(policy && policy.enabled);
}

function validate(input) {
  const required = ["agentId", "tool", "resourceIds"];
  for (const key of required) {
    if (!(key in input)) return key + " is required";
  }
  if (!Array.isArray(input.resourceIds) || input.resourceIds.length === 0) return "resourceIds must contain at least one resource";
  return null;
}

function evaluateAction(store, input, context = {}) {
  const state = store.getState();  if (input.requestId) {    const existing = state.actions.find((action) => action.requestId === input.requestId);    if (existing) return existing;  }
  const invalid = validate(input);
  if (invalid) {
    return {
      id: id("ACT"),
      decision: "BLOCK",
      downstreamExecution: "DENIED",
      riskScore: 100,
      classification: "UNKNOWN",
      matchedPolicies: ["POL-SCHEMA"],
      sequenceViolation: false,
      explanation: invalid
    };
  }

  const agent = state.agents.find((item) => item.id === input.agentId);
  const resources = input.resourceIds.map((resourceId) => state.resources.find((item) => item.id === resourceId)).filter(Boolean);
  const destination = input.destinationId ? state.destinations.find((item) => item.id === input.destinationId) : null;
  const classification = resources.length ? strongestClassification(resources) : "UNKNOWN";
  const priorActions = context.priorActions || [];
  const priorRestricted = priorActions.some((action) => action.classification === "RESTRICTED");
  const outbound = outboundTools.has(input.tool);
  const matchedPolicies = [];
  let decision = "ALLOW";
  let riskScore = sensitivityRank[classification] || 80;
  let explanation = "Authorization request allowed by active policies.";
  const riskFactors = [{ label: "Resource sensitivity", value: classification, score: sensitivityRank[classification] || 80 }];

  if (!agent || !agent.allowedTools.includes(input.tool)) {
    if (enabled(state, "POL-TOOL-PERMISSION")) matchedPolicies.push("POL-TOOL-PERMISSION");
    decision = "BLOCK";
    riskScore = Math.max(riskScore, 90);
    explanation = "Agent is not authorized to use this tool.";
  }

  if (!resources.length) {
    decision = "BLOCK";
    riskScore = 100;
    explanation = "Authorization request references an unknown resource.";
  }

  if (outbound && input.destinationId && !destination) {
    decision = "BLOCK";
    riskScore = 100;
    explanation = "Authorization request references an unknown destination.";
  }

  if (outbound) {    riskScore += 10;    riskFactors.push({ label: "Outbound action", value: input.tool, score: 10 });  }  if (priorRestricted && outbound) {    riskScore += 15;    riskFactors.push({ label: "Sequence context", value: "Prior restricted data access", score: 15 });  }  if (destination && destination.trust === "APPROVED_EXTERNAL") {    riskScore += 5;    riskFactors.push({ label: "Destination trust", value: destination.trust, score: 5 });  }  if (destination && destination.trust === "EXTERNAL_REVIEW_REQUIRED") {    riskScore += 10;    riskFactors.push({ label: "Destination trust", value: destination.trust, score: 10 });  }  if (destination && destination.trust === "PROHIBITED_EXTERNAL") {    riskScore += 25;    riskFactors.push({ label: "Destination trust", value: destination.trust, score: 25 });  }

  if (decision === "ALLOW" && outbound && classification === "RESTRICTED" && destination && destination.trust === "PROHIBITED_EXTERNAL" && enabled(state, "POL-RESTRICTED-PROHIBITED")) {
    matchedPolicies.push("POL-RESTRICTED-PROHIBITED");    riskFactors.push({ label: "Hard-deny policy", value: "POL-RESTRICTED-PROHIBITED", score: 100 });
    decision = "BLOCK";
    riskScore = 100;
    explanation = "Restricted data cannot be sent to a prohibited external destination. Downstream execution denied.";
  } else if (decision === "ALLOW" && outbound && classification === "RESTRICTED" && destination && destination.trust === "APPROVED_EXTERNAL" && (!input.approved || !input.redacted)) {    matchedPolicies.push("POL-CONFIDENTIAL-APPROVAL");    riskFactors.push({ label: "Restricted external handling", value: "Approval and redaction required", score: 90 });    decision = "REQUIRE_APPROVAL";    riskScore = Math.max(riskScore, 90);    explanation = "Restricted external transfer requires approval and redaction before downstream execution.";  } else if (decision === "ALLOW" && outbound && classification === "CONFIDENTIAL" && !input.approved && !input.redacted && enabled(state, "POL-CONFIDENTIAL-APPROVAL")) {
    matchedPolicies.push("POL-CONFIDENTIAL-APPROVAL");    riskFactors.push({ label: "Approval gate", value: "Missing approval/redaction", score: 82 });
    decision = "REQUIRE_APPROVAL";
    riskScore = Math.max(riskScore, 82);
    explanation = "Confidential outbound transfer requires approval or redaction before execution.";
  } else if (decision === "ALLOW" && outbound && ["CONFIDENTIAL", "RESTRICTED"].includes(classification) && (!destination || destination.trust === "UNKNOWN") && enabled(state, "POL-UNKNOWN-DESTINATION")) {
    matchedPolicies.push("POL-UNKNOWN-DESTINATION");    riskFactors.push({ label: "Unknown destination", value: destination ? destination.trust : "missing", score: 88 });
    decision = "BLOCK";
    riskScore = Math.max(riskScore, 88);
    explanation = "Sensitive data cannot be sent without a known approved destination.";
  }

  riskScore = Math.min(100, riskScore);
  const downstreamExecution = decision === "ALLOW" ? "AUTHORIZED" : "DENIED";
  const executionResult = decision === "ALLOW"
    ? { ok: true, executor: "safe-local-mock", tool: input.tool, message: "Safe local mock executor ran after authorization." }
    : null;
  const action = {
    id: id("ACT"),    requestId: input.requestId || null,
    timestamp: new Date().toISOString(),
    workflowId: context.workflowId || null,
    agentId: input.agentId,
    tool: input.tool,    operation: input.operation || input.tool,
    resourceIds: input.resourceIds,    source: input.source || "local-request",    requestedPermissions: Array.isArray(input.requestedPermissions) ? input.requestedPermissions : [input.tool],    parameters: input.parameters && typeof input.parameters === "object" ? input.parameters : {},
    destinationId: input.destinationId || null,
    classification,
    decision,
    riskScore,
    matchedPolicies,
    sequenceViolation: priorRestricted && outbound && decision !== "ALLOW",
    explanation,    riskFactors,    downstreamExecution,    mockToolExecuted: decision === "ALLOW",    executed: decision === "ALLOW",    executionResult,    safeAlternatives: decision === "ALLOW" ? [] : [      "Use an approved internal destination.",      "Apply redaction and request human approval.",      "Create a narrower agent permission set."    ]
  };
  return store.addAction(action);
}

function runWorkflow(store, name, steps) {
  const workflowId = id("WF");
  const actions = [];
  for (const step of steps) {
    actions.push(evaluateAction(store, step, { workflowId, priorActions: actions }));
  }
  const workflow = {
    id: workflowId,
    name: String(name || "Authorization workflow"),
    createdAt: new Date().toISOString(),
    actionIds: actions.map((action) => action.id),
    finalDecision: actions.length ? actions[actions.length - 1].decision : "NO_ACTIONS"
  };
  store.addWorkflow(workflow);
  return { workflow, actions };
}

module.exports = { evaluateAction, runWorkflow, strongestClassification };
