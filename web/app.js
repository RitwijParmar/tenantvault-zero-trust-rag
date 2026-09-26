const state = { tokens: {}, current: "northstar" };
const el = (id) => document.getElementById(id);
const walkthrough = [
  { target: "identity", kicker: "OPENING", title: "This is not a tenant filter.", description: "The workspace inherits its tenant from a verified identity. The browser never sends a selectable tenant ID with the query.", script: "Most RAG demos promise tenant filtering. I wanted the tenant boundary to be impossible to choose from the client in the first place." },
  { target: "scorecard", kicker: "MEASURED RISK", title: "Show the cost of one missing filter.", description: "Across 12 tenants and 576 synthetic documents, a deliberately global vector search selected the foreign canary in all 132 attack paths. TenantVault returned zero foreign sources in those same paths.", script: "I did not want a green test badge to be the proof. I injected the failure we worry about, measured the unsafe baseline, and then showed that the tenant-scoped path returns zero foreign sources." },
  { target: "identity-control", kicker: "IDENTITY", title: "The tenant claim arrives signed.", description: "If someone changes a header or slips tenant_id into JSON, the API rejects it. The service trusts only the credential claim.", script: "This is the first important move: the identity tells us who you are and which customer boundary applies. It is not a dropdown the request gets to control." },
  { target: "rls", kicker: "DATABASE", title: "The vector database is the enforcement point.", description: "Each request opens a transaction and sets a local tenant context. PostgreSQL FORCE RLS applies that context to every vector and audit row.", script: "Even if a developer accidentally forgets a WHERE clause, the database still refuses rows outside this tenant. That is the control I would want in a real company." },
  { target: "receipt", kicker: "EVIDENCE", title: "Every answer carries a proof.", description: "The receipt records the tenant, visible corpus size, source hashes, policy revision, and audit-chain head, then signs that exact set.", script: "Instead of asking a customer to trust an AI answer, we hand them an artifact that says exactly what tenant boundary and evidence set produced it." },
  { target: "probe", kicker: "RED TEAM", title: "Now try to break it.", description: "This button looks for the other demo tenant's deliberately sensitive canary. A passing result means it never entered the retrieval set.", script: "The strongest part of the demo is not the green badge. It is that we can ask the system for another tenant's canary and watch it come back empty." },
  { target: "probe", kicker: "CLOSE", title: "The model never gets a chance to leak it.", description: "The model only sees source chunks released after identity, transaction context, RLS, and tenant-key decryption have all agreed.", script: "That is the core idea: make the safe path the only path. The AI can be useful, but it cannot cross a customer boundary it never had access to." }
];
let guideIndex = 0;

function auth() { return { "Content-Type": "application/json", Authorization: `Bearer ${state.tokens[state.current]}` }; }
function short(value, left = 10) { return `${value.slice(0, left)}…${value.slice(-6)}`; }
function setIdentity() {
  const name = state.current === "northstar" ? "Northstar Health" : "Acme Robotics";
  el("identity").innerHTML = "";
  const icon = document.createElement("span"); icon.className = "tiny-shield"; icon.textContent = "◈";
  const message = document.createElement("span"); message.textContent = `${name} signed tenant context · caller cannot override tenant ID`;
  el("identity").append(icon, message);
}
async function request(path, body) {
  const res = await fetch(path, { method: "POST", headers: auth(), body: body ? JSON.stringify(body) : undefined });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Request failed");
  return data;
}
function renderReceipt(receipt) {
  el("receipt-state").textContent = "SIGNED"; el("receipt-state").className = "status good";
  const rows = [
    ["BOUND TENANT", short(receipt.tenant_id)],
    ["VISIBLE CORPUS", `${receipt.search_space_count} encrypted chunk${receipt.search_space_count === 1 ? "" : "s"}`],
    ["EVIDENCE SET", `${receipt.result_document_hashes.length} source hash${receipt.result_document_hashes.length === 1 ? "" : "es"}`],
    ["POLICY", "RLS + tenant keys + receipt"],
    ["SIGNATURE", short(receipt.signature, 13)]
  ];
  el("receipt").innerHTML = "";
  const grid = document.createElement("div"); grid.className = "receipt-grid";
  rows.forEach(([key, value]) => { const row = document.createElement("div"); const k = document.createElement("span"); const v = document.createElement("code"); k.textContent = key; v.textContent = value; row.append(k, v); grid.append(row); });
  const note = document.createElement("p"); note.textContent = `Request ${short(receipt.request_id)} · audit chain advanced`;
  el("receipt").append(grid, note);
}
function renderAnswer(data) {
  el("answer").className = "answer"; el("answer").innerHTML = "";
  const label = document.createElement("span"); label.className = "answer-label"; label.textContent = "GROUNDED RESPONSE";
  const text = document.createElement("p"); text.textContent = data.answer;
  el("answer").append(label, text);
  el("sources").innerHTML = "";
  data.sources.forEach((source, i) => { const card = document.createElement("article"); card.className = "source"; const title = document.createElement("strong"); title.textContent = `${i + 1}. ${source.title}`; const excerpt = document.createElement("p"); excerpt.textContent = source.excerpt; const score = document.createElement("span"); score.textContent = `${Math.round(source.score * 100)}% semantic match`; card.append(title, excerpt, score); el("sources").append(card); });
  renderReceipt(data.isolation_receipt);
}
async function runQuery(question) {
  el("answer").className = "answer loading"; el("answer").textContent = "Retrieving only inside your signed tenant boundary…";
  try { renderAnswer(await request("/v1/query", { question, top_k: 3 })); }
  catch (error) { el("answer").className = "answer error"; el("answer").textContent = error.message; }
}
async function boot() {
  const tokens = await fetch("/api/demo/tokens").then(r => r.json());
  state.tokens = { northstar: tokens.northstar.token, acme: tokens.acme.token };
  setIdentity();
}
el("tenant").addEventListener("change", (event) => { state.current = event.target.value; setIdentity(); el("answer").className = "answer empty"; el("answer").textContent = "Identity changed. The next query receives a new tenant-scoped proof."; el("sources").innerHTML = ""; el("receipt").textContent = "Run a retrieval to mint a signed, tenant-scoped receipt."; el("receipt-state").textContent = "WAITING"; el("receipt-state").className = "status neutral"; });
el("query-form").addEventListener("submit", (event) => { event.preventDefault(); runQuery(el("question").value); });
document.querySelectorAll("[data-question]").forEach(button => button.addEventListener("click", () => { el("question").value = button.dataset.question; runQuery(button.dataset.question); }));
el("probe").addEventListener("click", async () => { const result = el("probe-result"); result.className = "probe-result loading"; result.textContent = "Searching with the caller's signed context…"; try { const data = await request("/v1/isolation/probe"); result.className = `probe-result ${data.status}`; result.textContent = data.status === "passed" ? "PASS — no cross-tenant canary entered the retrieval set." : "FAIL — canary was visible. Investigate immediately."; renderReceipt(data.receipt); } catch (error) { result.className = "probe-result failed"; result.textContent = error.message; } });
function renderGuide() {
  const step = walkthrough[guideIndex];
  document.querySelectorAll(".guide-focus").forEach(node => node.classList.remove("guide-focus"));
  const target = document.querySelector(`[data-guide="${step.target}"]`);
  target.classList.add("guide-focus");
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  el("guide-count").textContent = `${String(guideIndex + 1).padStart(2, "0")} / ${String(walkthrough.length).padStart(2, "0")}`;
  el("guide-kicker").textContent = step.kicker;
  el("guide-title").textContent = step.title;
  el("guide-description").textContent = step.description;
  el("guide-script").textContent = step.script;
  el("guide-back").disabled = guideIndex === 0;
  el("guide-next").innerHTML = guideIndex === walkthrough.length - 1 ? "Finish walkthrough <span>✓</span>" : "Next point <span>→</span>";
  requestAnimationFrame(() => { const rect = target.getBoundingClientRect(); const marker = el("guide-marker"); marker.hidden = false; marker.style.transform = `translate(${Math.max(8, rect.left - 14)}px, ${Math.max(8, rect.top - 16)}px)`; });
}
function closeGuide() { el("guide-popup").hidden = true; el("guide-marker").hidden = true; document.querySelectorAll(".guide-focus").forEach(node => node.classList.remove("guide-focus")); }
el("guide-toggle").addEventListener("click", () => { guideIndex = 0; el("guide-popup").hidden = false; renderGuide(); });
el("guide-close").addEventListener("click", closeGuide);
el("guide-back").addEventListener("click", () => { guideIndex = Math.max(0, guideIndex - 1); renderGuide(); });
el("guide-next").addEventListener("click", () => { if (guideIndex === walkthrough.length - 1) { closeGuide(); return; } guideIndex += 1; renderGuide(); });
boot().catch((error) => { el("identity").textContent = `Demo identity unavailable: ${error.message}`; });
