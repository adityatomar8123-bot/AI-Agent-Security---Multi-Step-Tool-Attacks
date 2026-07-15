# State-Space Mathematical Formulation

This document models the agent-tool interaction space as a formal state-space system.

## Formal State-Space System

We model the environment as a deterministic transition system with hidden states:

$$\mathcal{M} = \langle \mathcal{S}, \mathcal{A}, \mathcal{T}, s_0, \mathcal{O}, \Phi \rangle$$

Where:
*   $\mathcal{S}$ is the set of hidden environment states (sandbox file contents, mailbox items, system processes, agent memory).
*   $\mathcal{A}$ is the set of user messages (actions / prompts).
*   $\mathcal{T}: \mathcal{S} \times \mathcal{A} \rightarrow \mathcal{S}$ is the transition function mapping the current state and prompt to the next state:
    $$s_{t+1} = \mathcal{T}(s_t, a_t)$$
*   $s_0$ is the initial environment state after reset.
*   $\mathcal{O}$ is the set of observable execution traces (logs of called tools, arguments, return outcomes, stdout).
*   $\Phi: \mathcal{S} \times \mathcal{A} \rightarrow \mathcal{O}$ is the observation function mapping the state transition to a trace:
    $$o_t = \Phi(s_t, a_t)$$

## Projection Mapping (Cell Partitioning)

The state-space $\mathcal{S}$ is extremely large and cannot be fully enumerated. We define an equivalence projection function $\Psi: \mathcal{O} \rightarrow \mathcal{C}$ mapping an observation trace to a discrete cell signature:

$$c_t = \Psi(o_t)$$

Where $\mathcal{C}$ is the set of cell signatures. We define two states $s_1, s_2 \in \mathcal{S}$ as equivalent ($s_1 \sim s_2$) if they produce the same cell signature under the same observation trace sequence.

## Reachability and Search Tree

A state $s_k$ is reachable from $s_0$ if there exists a sequence of prompts $\langle a_0, a_1, \dots, a_{k-1} \rangle$ such that:

$$s_k = \mathcal{T}(\dots \mathcal{T}(s_0, a_0) \dots, a_{k-1})$$

Our search algorithms explore this reachability graph. The `Archive` stores exemplars representing visited cells $c \in \mathcal{C}$. Each exemplar caches:
1.  A restorable snapshot of the hidden state $s \in \mathcal{S}$.
2.  The sequence of actions $\langle a_0, \dots, a_{k-1} \rangle$ that reached it.
3.  The cell signature $c \in \mathcal{C}$.
