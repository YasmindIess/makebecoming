# FORGE/0 — Execution roadmap

**Baseline:** V2 Latency & Confluence single-file SVG artwork and browser-local omission JSONL export. **Not yet:** a canonical hash chain, replay/import, C simplicial engine, actual confluent-minima controller, authorization, persistent node, or decentralized network.

**Goal:** a small, verifiable computational kernel that can represent positions, relations, bounded grants, projections, reconstruction candidates, and append-only causal histories; run as a private local node; synchronize verifiably; render a participant-facing world; and finally compile different campaigns from one trusted unit registry.

## Constitution — six invariant classes

- `trace`: source input records and causal references remain recoverable within their declared retention policy.
- `distinction`: a relation never silently equates distinct sources.
- `authorization`: recognizing a relation is never permission to execute an effect.
- `return`: admitted transitions preserve valid future examination and an append-only correction pathway.
- `position`: each declared positional persistence goal is evaluated on its own observables, rather than by geometric identity.
- `claim`: inferred, simulated, reported, attested, and directly measured are distinct epistemic classes.

**Non-claims:** a valid digital model is not proof of physical quantum-state fidelity, or an ability to recover private consciousness/qualia; an appended hash is not proof of a real-world occurrence; direct IPv6 is not anonymity; a second peer is not automatically Byzantine fault-tolerant consensus.

## The four epochs and fourteen chapters

| Chapter | Deliverable | Smallest meaningful exit criterion |
|---|---|---|
| **Epoch I: Evidential Nucleus** |||
| 1. Frozen omission semantics | V2.1 with immutable `o, lambda, b, Gamma` per event, separate hypothetical/counterfactual projections | Replay does not rewrite an old boundary when sliders change; reproducible import/export |
| 2. Typed/canonical event protocol | JSON5 human config → strict schema → RFC 8785 JCS canonical JSON → SHA-256 content address → JSONL | Independent implementations produce identical bytes/digests for reference fixtures |
| 3. Native C simplicial kernel | Vertices/edges/faces/tetrahedra with oriented boundary operators and face closure; JSONL I/O | `boundary(boundary(simplex))=0` for all supported dimensions; same binary handles deterministic input |
| 4. Local immutable journal | Append-only events, parent CID DAG, indexed heads, correction/reinterpretation events, cold replay, crash-safe writes | Export a corpus, erase indexes, rebuild from blocks, and reproduce the accepted state and heads |
| **Epoch II: Regenerative Forge** |||
| 5. Multiscale relational field | Positional persistence goals, diagonal operators, incidence/adjacency graphs, measured topological changes | Every displayed relation links to its source records and declared generation/position mapping |
| 6. Occlusion/projection | Private/public projections, scoped retention, redaction, multiple compatible reconstruction candidates | Different projections preserve permitted provenance while never disclosing private fields by default |
| 7. Grants and BECOME | Bounded grants, explicit effect types, nonce replay safety, PHP orchestration and native C unit registry | Unauthorized effect is rejected; accepted effect produces receipt with exact grant and causal ancestry |
| 8. Confluent-minima dynamics | Declared potential function, admissible neighbors, local stability/termination, reconciliation witnesses | Two divergent branches either reconcile with an inspectable witness or remain explicitly incompatible |
| **Epoch III: Distributed Substrate** |||
| 9. Forge Node 0 | Persistent localhost service, identity, signed events, local content address store, PHP/C interface, isolated keys | One host restarts and verifies its own sealed history without internet access |
| 10. IPv4/IPv6 + privacy transport | Transport-independent identity, optional IPv6, proxy observation schema, privacy-overlay mode, restricted logging | Same event digest over both IP versions; privacy mode emits no direct public peer endpoint |
| 11. Peer replication & merge | Inventory/heads exchange, request-by-CID, branch preservation, deterministic acceptance policies | Two disconnected peers produce forks, reconnect, verify blocks and preserve or explicitly reconcile branches |
| **Epoch IV: Participatory World** |||
| 12. Live generative projection | SVG renderer consumes kernel/journal stream; inspector can answer *why is this visible?* | Each visible fracture, bridge, minimum and relationship resolves to computed evidence |
| 13. MAKE BECOMING campaign | Seed field, permitted participant actions, local/public participation, witnessable outcome ledger | New participation produces an actual admitted event, visibly changes the world, and survives reload/replay |
| 14. Operational readiness and launch | Restricted ingest, recovery, migration, privacy review, performance budgets, optional release attestations | Restore from backup; bounded load accepted; private/public deployments behave according to their declared scope |

## Final transition — General-purpose campaign compiler

- Define a versioned campaign manifest covering `seed`, `positions`, `goals`, `grants`, `unit registry`, `accumulators`, `projections`, `acceptance metrics`, and `termination`.
- Compile manifests to permission-bounded campaign execution plans, never to arbitrary untrusted executable code.
- Demonstrate **two different campaigns** running on the same signed event protocol, native kernel, and peer synchronization infrastructure without bespoke core changes.

## Releases, not endless checklists

| Release | Chapters | User-visible result |
|---|---|---|
| `V2.1: Truthful Latency` | 1–2 | Immovable historical events, import/replay, deterministic identifiers and downloadable JSONL |
| `R0: Forge Local Core` | 3–4 | Real C kernel, local content-addressed journal, offline rebuild |
| `R1: Forge Regeneration` | 5–8 | Actual topology, occlusion, grants, stable basins, candidate reconciliation, one BECOME primitive |
| `R2: Forge Node` | 9–11 | Persistent local machine node, verifiable P2P replication and privacy-preserving optional transport |
| `R3: MAKE BECOMING` | 12–14 | Public-friendly scene generated by actual kernel state, first campaign, reliability/privacy safeguards |
| `R4: Forge Campaign Compiler` | final | Different independently specified campaigns share one engine |

## Immediate V2 → V2.1 work package

1. Extract a pure `forge-model` function from the browser render code (`state + event -> next state`). No DOM access inside it.
2. Persist `o`, `lambda`, its units, mapping from latency to spatial divergence, `b`, `Gamma`, amplitude, model version, deterministic seed and causal parents *at event creation*.
3. Make sliders represent either **next-event parameters** or explicitly labeled **counterfactual preview**. Never allow a preview to mutate what the journal claims historically occurred.
4. Implement JSONL import + cold replay + an explicit playback point. A reloaded export must reproduce the same structure without rerandomization.
5. Use schema-validation and an RFC 8785 JCS implementation with official test vectors; do not treat sorting object keys in a custom recursive function as proof of JCS compliance.
6. Add event-hash and parent-hash fields via a documented domain-separated digest convention, excluding the record's own hash from the hashed body. Distinguish a SHA-256 digest from a multicodec IPFS CID.
7. Add candidate minima analysis by evaluating a declared energy over a finite allowed neighborhood of transitions; display stable, provisional, and incompatible states distinctly. A lower visual dispersion score is not by itself a proof of convergence.
8. Keep the SVG dominant and responsive. Expose a compact evidence inspector for `origin / latency / first divergence / descendants / confidence`.
9. Ship one user-understandable capability: **MAKE BECOMING, export JSONL, clear state, import the JSONL, and see precisely the same recorded formation return.**

## Runtime division

- **C:** deterministic topology/mathematics, event validation, state transitions, optional WASM compilation for the browser.
- **PHP:** orchestration and campaign declarations, not heavy numerical loops or cryptographic primitives.
- **JSON5:** editable human authoring; **canonical JSON:** hash/sign basis; **JSONL:** event interchange and append-only ingestion.
- **Local blockstore / optional Kubo:** persistent, content-addressed bytes. A hash alone does not guarantee retention or replication.
- **Ed25519/X25519:** separate event signing and authenticated secure-transport duties using vetted libraries and protocol design.
- **OpenPGP:** optional release/build attestations; not a general event-authority substitute.
- **HEX-0/Stage0:** provenance research track for reproducible toolchain bootstrapping, kept off the launch critical path until a full audited chain works.
- **SVG public surface:** projection only, not canonical state.

## Hard distinctions

- An immutable event record must not be modified when a viewer adjusts reconstruction parameters.
- A signed event identifies a signer, not necessarily the truth of its physical claim.
- A simplicial complex must be closed under faces; adding a face may eliminate an existing homology class, not merely create topology.
- Regeneration may return several admissible states; none can be called the unique lost state without independent evidence.
- Eventual union of immutable DAG entries does not establish consensus over conflicting financial or authority-bearing effects.
- Two copies on the same disk do not provide independent decentralized persistence.
- Privacy overlays reduce location disclosure; no universal anonymity guarantee exists.
- Do not bind Forge's transport identity to IPv6 or publish local IP address metadata by default.
- Do not publish, deploy, or bind a new Blochfield domain without separate scope authorization.

## The release-defining vertical slice

```
Create an omission/diagonal event
  → freeze its mathematical meaning
  → validate its schema and grant
  → calculate a state transition in native C
  → append the canonical event to JSONL and content address its block
  → inspect a rendered SVG projection
  → restart and replay to the same result
  → send block to second peer
  → verify/reconcile and display the same causal ancestry.
```

This one slice is more valuable than implementing many disconnected modules. Once it works locally, scale, transport, campaigns, and generality become extensions rather than rewrites.