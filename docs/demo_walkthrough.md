# TenantVault interview walkthrough

**Format:** 4–5 minutes. Open the deployed URL, select **Northstar Health**, and click **Present this demo**. The presenter panel gives you a moving marker and short, human-sounding cues. Do not read every word—use the ideas, pause, and let the live proof do the work.

## 1. Open with the real problem — 25 seconds

“A lot of companies want an AI copilot over customer data, but one failure mode is unacceptable: Tenant A’s question cannot surface Tenant B’s embeddings or documents. I built TenantVault to make that a database-enforced property, not a prompt or a convention in app code.”

Point to the **Present this demo** button and say: “I added this presenter mode so the implementation can explain itself while I walk through the controls.”

## 2. Identity is the start of the boundary — 40 seconds

Advance to the signed-identity marker.

“First, look at this tenant context. The browser never gets to submit a tenant_id. The API derives it from the signed identity claim. If somebody edits a header or sneaks a tenant ID into the JSON payload, we reject the request. That avoids the classic confused-deputy bug where a well-meaning backend trusts the client to name the customer partition.”

## 3. Do one useful retrieval — 45 seconds

Ask: **Who owns the cardiac escalation review?**

“Now I’m asking a normal operational question. The answer is source-grounded, and I can see the evidence card beneath it. What matters is what you do *not* see: the retriever did not search a global corpus and then filter a response. It only received chunks that Northstar is allowed to see.”

## 4. Show the control that matters — 55 seconds

Advance to **VECTOR STORE**.

“This is the core design choice. The request opens a PostgreSQL transaction and sets a transaction-local tenant context. Both the pgvector table and the audit table have FORCE ROW LEVEL SECURITY. Even if someone accidentally writes a query without a tenant filter, the database still won’t release another tenant’s rows. The application role is deliberately not a database owner or superuser, so it cannot bypass that policy.”

## 5. Make the output auditable — 40 seconds

Advance to **Isolation receipt**.

“Every retrieval also produces this receipt. It binds the tenant, the policy version, how many chunks were visible, hashes of the returned sources, and the head of a hash-chained audit log. Then it signs that exact bundle. So when a customer asks, ‘what data did the AI use?’, we have something stronger than an application log or a promise.”

## 6. Let them watch the attack fail — 45 seconds

Advance to **Run isolation challenge** and click it.

“Last, I try to retrieve the other demo tenant’s intentionally sensitive canary. This is a practical red-team check—not just a green security slide. The canary is not in the result set, and the receipt proves the visible corpus was only Northstar’s. The important point is that the model never got an opportunity to reveal it.”

## Close — 20 seconds

“The takeaway is simple: useful RAG does not need to trade away tenant isolation. Signed identity chooses the boundary, the database enforces it, tenant-bound encryption provides a second fence, and every answer leaves a verifiable trail.”

## If they go deeper

- **“Why not just use a `WHERE tenant_id`?”** “We do not rely on it. RLS is evaluated by PostgreSQL even when a query omits that condition.”
- **“Can the server accidentally reuse a tenant connection?”** “No. The context is set transaction-locally, so it resets at transaction end.”
- **“Is the demo token system production auth?”** “The demo uses a compact HMAC issuer to run without an identity provider. The production seam is an OIDC JWKS verifier; the invariant is that tenant identity comes from verified claims, not the request payload.”
- **“What does Cloud Run add?”** “The public demo runs on Cloud Run. The RLS migration runs as a separate Cloud Run Job, while the runtime service gets a non-owner database role and only its own Secret Manager entries.”
