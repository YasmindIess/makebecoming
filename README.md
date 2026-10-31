# MAKE BECOMING — FORGE/0

An evolving **Fracture & Agency Forge**: a generative SVG observatory backed by a native C simplicial kernel and a private, local PHP content-addressed journal.

**[Open the live observatory](https://makebecoming.vercel.app)** · [Roadmap](docs/roadmap.md)

## What actually runs

- **Web / `index.html`:** Forge V2.1. A standalone interactive SVG with omission-event origins, latency, divergence boundaries, counterfactual views, a declared finite minima model and downloadable/importable hash-linked JSONL. It runs entirely in your browser. No public event database, wallets, or live peer networking are connected.
- **Native / `src/forge.c`:** FORGE R0, a C11 executable that independently validates the restricted V2.1 JSONL format, derives vertices, edges, faces and tetrahedra, and checks the simplicial identity `boundary(boundary(simplex)) = 0`.
- **Local / `runtime/forge-store.php`:** An optional private, filesystem-backed journal that appends content-addressed blocks and cold-replays them through the native verifier. The mutable HEAD is not independently witnessed, signed or replicated.
- **`docs/roadmap.md`:** Four epochs, fourteen chapters and the general-purpose campaign-compiler transition.

## Local native run (Linux / WSL2)

Requires `gcc` (or another C11 compiler), `make`, `libssl-dev`, PHP CLI 8.1+, Python 3 for tests.

```sh
sudo apt install build-essential libssl-dev php-cli python3
make
make test
./forge-kernel replay examples/v2_1_verified.jsonl --topology /tmp/forge-topology.jsonl
php runtime/forge-store.php append examples/v2_1_verified.jsonl "$HOME/.local/share/makebecoming"
php runtime/forge-store.php replay "$HOME/.local/share/makebecoming"
```

To view the web experience locally, use a local HTTP server (`python3 -m http.server 8000`) and visit `http://localhost:8000`. The Web Crypto API used for the event digest needs a secure context (HTTPS or localhost).

## Data / security boundaries

The records represent **simulated** events. Digests and parent hashes make record alterations detectable, but do not prove real-world occurrences, anonymity, consensus, or external timestamping. The current canonical JSON scheme is an explicitly **restricted ASCII/integer schema**, not full RFC 8785. The native C core and PHP CLI do not execute on Vercel; Vercel hosts the static browser view. No public API, token issuance, or autonomous external action is enabled.

Forge does not claim quantum hardware, measurable qualia, fully deployed HEX-0 bootstrapping, or decentralized storage. Those are separate research/development stages.

## Repository layout

```text
index.html                browser-only Forge V2.1
src/forge.c               native C simplicial kernel
runtime/forge-store.php   localhost/private block journal
examples/                 deterministic example and topology output
tests/                    native and storage checks
docs/roadmap.md           full development route
Makefile                  native build and tests
```

`MAKE BECOMING` currently means **one reproducible simulated relational change**; future grant enforcement, independent replication, and campaign compilation must be implemented and audited before making broader claims.