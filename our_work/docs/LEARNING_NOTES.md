# Learning Notes: Algorithmic Attack Discovery

Welcome! This document provides educational commentary on the algorithms, design invariants, and principles behind the Attack Discovery Engine.

## Why Algorithmic Search Matters

Prompt engineering (manually crafting prompts) is static and fragile. An AI agent's security guardrails change, system files shift, and LLM behaviors drift. 

By treating vulnerability discovery as an **algorithmic search problem**, we build a system that:
1.  Automatically probes the environment.
2.  Discovers what tools are available and how they respond.
3.  Synthesizes multi-step attack payloads dynamically.
4.  Learns and updates its attack strategy based on trace feedback.

## Key Design Patterns & Insights

### 1. State Transposition (The Archive)
In complex game-trees, different paths often lead to the same state. For example:
*   Action A: `read email` -> Action B: `read config`
*   Action B: `read config` -> Action A: `read email`

Both sequences result in the agent knowing the contents of both email and config. In chess, this is a **transposition**. 

The `Archive` acts as a **Transposition Table**. By hashing the normalized trace representation into a `CellSignature`, we avoid visiting the same state multiple times, saving computing cycles and maximizing search depth.

### 2. State Restoration (Go-Explore)
Traditional search engines (like DFS or Monte Carlo rollouts) return to a state by replaying all previous actions from the root node. In an environment with an LLM agent, this is extremely slow and unreliable: the agent might respond differently on replay, breaking the chain.

By utilizing `env.snapshot()` and `env.restore(snapshot)`, we perform **teleportation**. We return to a deep state instantly, bypassing agent drift and ensuring search consistency.

### 3. Pruning Refusals
If a prompt causes the agent to say *"I'm sorry, I cannot perform that task,"* we get zero tool events. Continuing to search from this state is a waste of resources. 

We immediately **prune** this branch, equivalent to Alpha-Beta pruning cutting off hopeless moves in chess.
