# T-Trace v0.1 Specification

## 1. Purpose

T-Trace is a format for recording acknowledged state transitions. It solves the problem of maintaining continuity of meaning in long-lived interactions by capturing only those state changes that have been explicitly recognized.

T-Trace originated from the needs of continuity-preserving protocols such as Liminal Thread Protocol (LTP), but is defined as a protocol-agnostic format.

## 2. Core Concepts

*   **Transition**: A discrete modification of state.
*   **Thread**: A logical context representing continuity over time.
*   **Acknowledgement**: Explicit confirmation that a transition is valid and accepted.
*   **Append-only Principle**: The trace is an immutable sequence of records; history is preserved by addition, never modification.

## 3. Record Structure

T-Trace uses the JSON Lines format (newline-delimited JSON).

### Minimal Required Fields

Each record MUST contain:

*   `id`: Identifier unique within the trace stream or generation context.
*   `type`: The record type.
*   `ts`: Timestamp indicating when the transition was acknowledged (ISO 8601 or Unix epoch).
*   `thread_id`: Identifier of the associated thread.

### Optional Fields

Fields beyond the required set are permitted only when strictly necessary to describe the payload of the transition.

## 4. Allowed Record Types

The canonical set of record types is restricted to:

*   `sense`: Represents the admission of external input into the thread context.
*   `transition`: Represents a proposed change of state.
*   `commit`: Represents the acknowledgement and finalization of a state change.

## 5. Invariants

*   **Immutability**: Existing records must not be altered or deleted.
*   **Causality**: Records within a thread must respect causal ordering.
*   **Format Strictness**: Each line must be a valid JSON object.
*   **Scope**: The format defines structure, not transport or storage.
