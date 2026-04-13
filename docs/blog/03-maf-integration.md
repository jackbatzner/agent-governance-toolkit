# What Happens When Your Banking Agent Sees a Social Security Number?

A banking agent that leaks a Social Security number creates regulatory liability under Gramm-Leach-Bliley. A healthcare agent that shares a diagnosis across departments violates HIPAA. A DevOps agent that deploys to production without approval can take down infrastructure. Even a small startup's customer support bot can accidentally expose credit card numbers if nobody told the agent not to include them in responses.

Same governance engine. Completely different policies.

That's the premise behind our [five-industry example](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/maf-integration) for the [Microsoft Agent Framework](https://github.com/microsoft/agents). Instead of a generic "here's how governance works" demo, we built five real scenarios—banking, retail, healthcare, enterprise IT, and DevOps—each with the threat models, data sensitivity profiles, and regulatory requirements that actually matter in that industry. The [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)—an open-source runtime security layer for AI agents—provides the enforcement engine. YAML provides the rules. The rules are what change between industries.

## The policy, not the code, is the product

Here's the loan processing agent's governance policy:

```yaml
name: "loan_governance"
rules:
  - name: "block_ssn_access"
    condition:
      field: "message"
      operator: "contains_any"
      value: "ssn,social security,tax id"
    action: "deny"
    priority: 100
    message: "PII access blocked by governance policy"
```

And here's the healthcare agent's policy that blocks protected health information from crossing department boundaries:

```yaml
name: "healthcare_governance"
rules:
  - name: "block_phi_sharing"
    condition:
      field: "message"
      operator: "contains_any"
      value: "diagnosis,medication,lab results,treatment plan"
    action: "deny"
    priority: 100
    message: "PHI cross-department access blocked"
```

Same YAML schema. Same enforcement engine. Completely different business rules. A compliance officer can read and modify these policies without touching Python or .NET code. That's the design intent—governance rules should be auditable by the people responsible for compliance, not just the engineers who built the agent.

## Five industries, five threat models

### Banking: Loan processing under PII governance

The agent evaluates applications, checks credit, and communicates with applicants. The policy layer blocks SSNs and tax IDs at the input level (before the LLM processes them), caps API spending, sandboxes which external APIs the agent can call, and monitors for anomalies—like an agent suddenly running 50 credit checks per minute, which triggers Z-score detection and auto-quarantine.

### Retail: Customer service with refund fraud prevention

The agent handles returns, refunds, and account inquiries. Governance caps refund amounts, flags suspicious refund patterns, blocks credit card numbers and CVVs from agent context, and enforces human escalation for high-value transactions and account closures.

### Healthcare: HIPAA-compliant agent isolation

This is where governance becomes a legal requirement, not a best practice. The policy layer blocks protected health information from crossing department boundaries—a cardiology agent cannot see oncology records even if both are in the same system. The agent cannot recommend medications. Data exfiltration attempts through indirect prompting are caught by pattern matching on the raw input.

### Enterprise IT: Helpdesk without privilege escalation

The threat model centers on privilege escalation. The agent can reset passwords and process software requests, but cannot access administrator credentials, elevate user permissions (those require human approval), or modify production infrastructure. It can query system status but not change it.

### DevOps: Deployment gates for autonomous operations

The highest-risk scenario. Production deployments require explicit approval—the agent can stage but not ship. Destructive operations (`DROP TABLE`, `rm -rf`, `kubectl delete`) are blocked unconditionally. Rapid successive deployments trigger circuit breaking, preventing the cascading-failure loops that automated rollback systems sometimes create.

## Python and .NET: Same YAML, same guarantees

Every scenario ships in both languages because enterprise teams don't all use the same stack. The governance policies are the same YAML files, shared between both implementations:

```python
# Python
from agent_os.policies.evaluator import PolicyEvaluator
from agent_os.integrations.maf_adapter import GovernancePolicyMiddleware
from agentmesh.governance.audit import AuditLog

evaluator = PolicyEvaluator()
evaluator.load_policies(Path("./policies"))
audit_log = AuditLog()
middleware = GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)

# Middleware intercepts inside the MAF pipeline — see full example for usage
```

Swap `Python` for `.NET` and the API shape is equivalent. The YAML doesn't change. This means a compliance team can define policies once and know they're enforced identically regardless of which language the agent team chose.

## Rogue detection: Catching what rules can't

Static policies catch known bad patterns. But what about an agent that stays within its allowed tools yet behaves abnormally? The rogue detection layer monitors behavioral signals—call frequency anomalies, tool diversity collapse, and capability deviation—and auto-quarantines agents that cross thresholds. The same detector works across all five industry scenarios with zero configuration changes.

## The audit trail isn't optional

Every policy decision, tool access check, and rogue detection event gets recorded in a Merkle-chained log. SHA-256 hashing means any modification—even changing a single character in a single entry—is detectable. This isn't logging for debugging. It's compliance evidence.

The EU AI Act's high-risk obligations take effect in August 2026. The Colorado AI Act becomes enforceable in June 2026. SOC 2 audits increasingly need to account for AI agent behavior. Organizations preparing for any of these need tamper-proof evidence that their agents operated within policy—not just assertions that they were "configured correctly."

## Apply this to your own agents

You don't need to be in banking or healthcare to benefit. The pattern works for any agent that handles sensitive data or takes real-world actions:

1. **Install:** `pip install agent-governance-toolkit[full]`
2. **Pick a scenario:** Start with the industry example closest to your use case and copy its YAML policy file.
3. **Customize the rules:** Change the `contains_any` values to match your data sensitivity (customer emails, API keys, internal URLs — whatever your agents shouldn't be touching).
4. **Wire the middleware:** Initialize `PolicyEvaluator` + `GovernancePolicyMiddleware` in your agent's startup code. The middleware intercepts before the LLM sees anything.

## Try it

```bash
git clone https://github.com/microsoft/agent-governance-toolkit
cd agent-governance-toolkit/examples/maf-integration

pip install agent-governance-toolkit[full]

# Run any scenario
cd 01-loan-processing/python && pip install -r requirements.txt && python main.py
cd ../../02-customer-service/python && pip install -r requirements.txt && python main.py
cd ../../03-healthcare/python && pip install -r requirements.txt && python main.py
cd ../../04-it-helpdesk/python && pip install -r requirements.txt && python main.py
cd ../../05-devops-deploy/python && pip install -r requirements.txt && python main.py
```

Set `OPENAI_API_KEY` or `GITHUB_TOKEN` for real LLM integration, or run with no API key for simulated responses that still demonstrate every governance behavior. The policies in `policies/` are yours to modify—change a rule, rerun the scenario, watch enforcement change.

> **Note:** The Python snippet above is abbreviated. See the [full scenario scripts](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/maf-integration) for complete, runnable code.

The [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) is MIT-licensed and open source.

The framework builds the agent. The policy defines what it's allowed to do. The governance layer makes sure it actually does it.
