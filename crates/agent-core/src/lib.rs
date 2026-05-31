//! `agent-core` — Deployable 1 · Data Plane / Tunneling (Part B §B.3.4). OPEN.
//! Hexagonal architecture per Part A §A.3.1.
pub mod domain;       // pure business logic, no I/O
pub mod application;  // use cases, orchestration
pub mod ports;        // trait interfaces for external systems
pub mod adapters;     // concrete impls of ports
