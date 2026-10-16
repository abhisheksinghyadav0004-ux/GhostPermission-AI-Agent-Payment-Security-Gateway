const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Store } = require("../lib/store");
const { evaluateAction, runWorkflow } = require("../lib/engine");

function tempStore() {
  const file = path.join(os.tmpdir(), "ghostpermission-test-" + Math.random().toString(16).slice(2) + ".json");
  const store = new Store(file);
  store.reset();
  return { store, file };
}

function addRealRecords(store) {
  const agent = store.createAgent({ name: "Local Browser Agent", allowedTools: ["read_document", "send_internal", "send_external"] });
  const publicResource = store.createResource({ name: "Internal policy page", owner: "Security Team", classification: "PUBLIC" });
  const restrictedResource = store.createResource({ name: "Privileged access export", owner: "Security Team", classification: "RESTRICTED" });
  const confidentialResource = store.createResource({ name: "Quarterly review file", owner: "Finance", classification: "CONFIDENTIAL" });
  const internal = store.createDestination({ name: "Security operations mailbox", trust: "APPROVED_INTERNAL" });
  const external = store.createDestination({ name: "Vendor review mailbox", trust: "EXTERNAL_REVIEW_REQUIRED" });
  const approvedExternal = store.createDestination({ name: "Approved external archive", trust: "APPROVED_EXTERNAL" });  const prohibited = store.createDestination({ name: "Unapproved external endpoint", trust: "PROHIBITED_EXTERNAL" });
  return { agent, publicResource, restrictedResource, confidentialResource, internal, external, approvedExternal, prohibited };
}

test("new workspace starts without placeholder entities or metrics", () => {
  const { store } = tempStore();
  const state = store.getPublicState();
  assert.equal(state.agents.length, 0);
  assert.equal(state.resources.length, 0);
  assert.equal(state.destinations.length, 0);
  assert.equal(state.metrics.totalActions, 0);
});

test("public document to approved internal destination is allowed", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  const action = evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_internal",
    resourceIds: [records.publicResource.id],
    destinationId: records.internal.id
  });
  assert.equal(action.decision, "ALLOW");
  assert.equal(action.downstreamExecution, "AUTHORIZED");
});

test("restricted prohibited outbound action is blocked before downstream execution", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  const action = evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_external",
    resourceIds: [records.restrictedResource.id],
    destinationId: records.prohibited.id
  });
  assert.equal(action.decision, "BLOCK");
  assert.equal(action.downstreamExecution, "DENIED");
  assert.equal(action.executionResult, null);
  assert.ok(action.matchedPolicies.includes("POL-RESTRICTED-PROHIBITED"));
});

test("confidential external transfer requires approval and is denied until approved", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  const action = evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_external",
    resourceIds: [records.confidentialResource.id],
    destinationId: records.external.id
  });
  assert.equal(action.decision, "REQUIRE_APPROVAL");
  assert.equal(action.downstreamExecution, "DENIED");
});

test("approved confidential transfer is authorized", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  const action = evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_external",
    resourceIds: [records.confidentialResource.id],
    destinationId: records.external.id,
    approved: true
  });
  assert.equal(action.decision, "ALLOW");
  assert.equal(action.downstreamExecution, "AUTHORIZED");
});

test("missing tool permission blocks request", () => {
  const { store } = tempStore();
  const agent = store.createAgent({ name: "Read Only Agent", allowedTools: ["read_document"] });
  const resource = store.createResource({ name: "Internal policy page", owner: "Security Team", classification: "PUBLIC" });
  const action = evaluateAction(store, {
    agentId: agent.id,
    tool: "send_external",
    resourceIds: [resource.id]
  });
  assert.equal(action.decision, "BLOCK");
  assert.ok(action.matchedPolicies.includes("POL-TOOL-PERMISSION"));
});

test("audit chain detects tampered records", () => {
  const { store, file } = tempStore();
  const records = addRealRecords(store);
  evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_external",
    resourceIds: [records.restrictedResource.id],
    destinationId: records.prohibited.id
  });
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  data.audit[0].details.decision = "ALLOW";
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  const reloaded = new Store(file);
  reloaded.load();
  assert.equal(reloaded.verifyAudit().valid, false);
});

test("invalid action schema is rejected", () => {
  const { store } = tempStore();
  const action = evaluateAction(store, { agentId: "agent-unknown" });
  assert.equal(action.decision, "BLOCK");
  assert.equal(action.downstreamExecution, "DENIED");
});

test("equivalent persisted inputs produce equivalent deterministic decision fields", () => {
  const first = tempStore();
  const second = tempStore();
  const aRecords = addRealRecords(first.store);
  const bRecords = addRealRecords(second.store);
  const a = evaluateAction(first.store, {
    agentId: aRecords.agent.id,
    tool: "send_external",
    resourceIds: [aRecords.restrictedResource.id],
    destinationId: aRecords.prohibited.id
  });
  const b = evaluateAction(second.store, {
    agentId: bRecords.agent.id,
    tool: "send_external",
    resourceIds: [bRecords.restrictedResource.id],
    destinationId: bRecords.prohibited.id
  });
  assert.equal(a.decision, b.decision);
  assert.equal(a.riskScore, b.riskScore);
  assert.deepEqual(a.matchedPolicies, b.matchedPolicies);
});


test("multi-step workflow detects individually permitted tools combined into prohibited sequence", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  const result = runWorkflow(store, "Restricted export sequence", [
    { agentId: records.agent.id, tool: "read_document", resourceIds: [records.publicResource.id] },
    { agentId: records.agent.id, tool: "read_document", resourceIds: [records.restrictedResource.id] },
    { agentId: records.agent.id, tool: "send_external", resourceIds: [records.restrictedResource.id], destinationId: records.prohibited.id }
  ]);
  assert.equal(result.actions[2].decision, "BLOCK");
  assert.equal(result.actions[2].sequenceViolation, true);
  assert.equal(result.actions[2].mockToolExecuted, false);
  assert.equal(store.getState().workflows.length, 1);
});

test("incident notes and exports persist with audit records", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_external",
    resourceIds: [records.restrictedResource.id],
    destinationId: records.prohibited.id
  });
  const incident = store.getState().incidents[0];
  store.updateIncident(incident.id, { status: "INVESTIGATING", note: "Confirmed restricted resource attempted to prohibited endpoint." });
  const report = store.exportIncident(incident.id);
  assert.equal(report.incident.notes.length, 1);
  assert.equal(report.auditVerification.valid, true);
  assert.ok(store.getState().audit.some((record) => record.type === "incident.exported"));
});

test("changing destination from approved to prohibited changes the outcome", () => {
  const { store } = tempStore();
  const records = addRealRecords(store);
  const approved = evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_internal",
    resourceIds: [records.restrictedResource.id],
    destinationId: records.internal.id
  });
  const prohibited = evaluateAction(store, {
    agentId: records.agent.id,
    tool: "send_external",
    resourceIds: [records.restrictedResource.id],
    destinationId: records.prohibited.id
  });
  assert.equal(approved.decision, "ALLOW");
  assert.equal(prohibited.decision, "BLOCK");
});
test("restricted data to approved external destination requires redaction and approval", () => {  const { store } = tempStore();  const records = addRealRecords(store);  const review = evaluateAction(store, {    agentId: records.agent.id,    tool: "send_external",    resourceIds: [records.restrictedResource.id],    destinationId: records.approvedExternal.id  });  const allowed = evaluateAction(store, {    agentId: records.agent.id,    tool: "send_external",    resourceIds: [records.restrictedResource.id],    destinationId: records.approvedExternal.id,    approved: true,    redacted: true  });  assert.equal(review.decision, "REQUIRE_APPROVAL");  assert.equal(review.mockToolExecuted, false);  assert.equal(allowed.decision, "ALLOW");  assert.equal(allowed.mockToolExecuted, true);});test("disabled restricted prohibited policy is not enforced", () => {  const { store } = tempStore();  const records = addRealRecords(store);  store.updatePolicy("POL-RESTRICTED-PROHIBITED", { enabled: false });  const action = evaluateAction(store, {    agentId: records.agent.id,    tool: "send_external",    resourceIds: [records.restrictedResource.id],    destinationId: records.prohibited.id  });  assert.equal(action.matchedPolicies.includes("POL-RESTRICTED-PROHIBITED"), false);});test("requestId prevents duplicate action persistence during retries", () => {  const { store } = tempStore();  const records = addRealRecords(store);  const input = {    requestId: "REQ-001",    agentId: records.agent.id,    tool: "send_internal",    resourceIds: [records.publicResource.id],    destinationId: records.internal.id  };  const first = evaluateAction(store, input);  const second = evaluateAction(store, input);  assert.equal(first.id, second.id);  assert.equal(store.getState().actions.filter((action) => action.requestId === "REQ-001").length, 1);});