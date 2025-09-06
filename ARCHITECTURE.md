# TSP Protocol - Visual Workflow

**Copyright (c) 2025 Vladislav Dunaev. All rights reserved.**  
**SPDX-License-Identifier: AGPL-3.0-or-Commercial**

This document contains visual diagrams and architectural documentation for TrueState Protocol (TSP).


## Complete TSP Lifecycle Diagram

```mermaid
graph TD
    A[User Credentials] --> B[Initialize TSP]
    B --> C{Artifact Type}
    
    C -->|WEB_AUTH| D1[Low Complexity<br/>~1 second]
    C -->|LICENSE| D2[Medium Complexity<br/>5-30 seconds]
    C -->|CERTIFICATE| D3[High Complexity<br/>30-120 seconds]
    C -->|NFT| D4[Max Complexity<br/>2-10 minutes]
    
    D1 --> E[Generate Seed + Nonce]
    D2 --> E
    D3 --> E
    D4 --> E
    
    E --> F[Proof-of-Work Mining]
    F --> G[Prime Number Generation]
    G --> H[Dual PoW Validation]
    
    H -->|Valid| I[Create Genesis Commitment]
    H -->|Invalid| F
    
    I --> J[Digital Signature]
    J --> K[Merkle Tree Integration]
    K --> L[Artifact Created]
    
    L --> M[Store in commits.json]
    
    %% Verification Branch
    M --> N[Artifact Verification]
    N --> O[Load Artifact Data]
    O --> P[Verify PoW]
    P --> Q[Verify Signatures]
    Q --> R[Verify Merkle Proof]
    R --> S[Check Ownership]
    
    S -->|Valid| T[Verification Success]
    S -->|Invalid| U[Verification Failed]
    
    %% Ownership Transfer
    T --> V{Transfer Needed?}
    V -->|Yes| W[Create Transfer Artifact]
    V -->|No| X[Use Artifact]
    
    W --> Y[New Owner Creates Artifact]
    Y --> Z[Transfer Chain Recorded]
    Z --> T
```

## Artifact Creation Process

```mermaid
sequenceDiagram
    participant U as User
    participant TSP as TSP Protocol
    participant C as Controller
    participant P as Prime Generator
    participant M as Merkle Tree
    participant S as Storage
    
    U->>TSP: Initialize with keys & model
    TSP->>C: Get model parameters
    C-->>TSP: Difficulty, memory cost, etc.
    
    TSP->>TSP: Generate random seed
    TSP->>TSP: Proof-of-Work mining
    
    loop Until PoW Valid
        TSP->>TSP: Try candidate seed
        TSP->>TSP: Check PoW difficulty
    end
    
    TSP->>P: Generate cryptographic prime
    P->>P: Mine prime with dual validation
    P-->>TSP: Valid prime number
    
    TSP->>TSP: Create genesis commitment
    TSP->>TSP: Sign with private key
    TSP->>M: Add to Merkle tree
    M-->>TSP: Root hash & proof
    
    TSP->>S: Store artifact
    S-->>U: Artifact ID & config hash
```

## Ownership Chain Verification

```mermaid
graph LR
    A[Alice Creates] --> B[Artifact for Bob]
    B --> C[Bob Verifies Ownership]
    
    C --> D{Bob Creates Transfer?}
    D -->|Yes| E[New Artifact for Charlie]
    D -->|No| F[Bob Uses Artifact]
    
    E --> G[Charlie Verifies]
    G --> H[Ownership Chain: Alice→Bob→Charlie]
    
    subgraph "Cryptographic Proofs"
        I[Genesis Signature]
        J[Designated Owner Hash]
        K[Merkle Tree Proof]
        L[PoW Validation]
    end
    
    C -.-> I
    C -.-> J
    C -.-> K
    C -.-> L
    
    G -.-> I
    G -.-> J
    G -.-> K
    G -.-> L
```

## Security Verification Flow

```mermaid
flowchart TD
    Start([Artifact Received]) --> Load[Load Artifact Data]
    
    Load --> Parse[Parse JSON Structure]
    Parse --> Meta{Metadata Valid?}
    
    Meta -->|No| Fail1[❌ Invalid Format]
    Meta -->|Yes| PoW[Verify Proof-of-Work]
    
    PoW --> PoWCheck{PoW Valid?}
    PoWCheck -->|No| Fail2[❌ Invalid PoW]
    PoWCheck -->|Yes| Sig[Verify Digital Signature]
    
    Sig --> SigCheck{Signature Valid?}
    SigCheck -->|No| Fail3[❌ Invalid Signature]
    SigCheck -->|Yes| Genesis[Verify Genesis Commitment]
    
    Genesis --> GenCheck{Genesis Valid?}
    GenCheck -->|No| Fail4[❌ Invalid Genesis]
    GenCheck -->|Yes| Merkle[Verify Merkle Proof]
    
    Merkle --> MerkleCheck{Merkle Valid?}
    MerkleCheck -->|No| Fail5[❌ Invalid Merkle]
    MerkleCheck -->|Yes| Owner[Check Ownership]
    
    Owner --> OwnerCheck{Owner Match?}
    OwnerCheck -->|No| Fail6[❌ Wrong Owner]
    OwnerCheck -->|Yes| Success[✅ Verified Authentic]
    
    style Success fill:#90EE90
    style Fail1 fill:#FFB6C1
    style Fail2 fill:#FFB6C1
    style Fail3 fill:#FFB6C1
    style Fail4 fill:#FFB6C1
    style Fail5 fill:#FFB6C1
    style Fail6 fill:#FFB6C1
```

## Component Architecture

```mermaid
graph TB
    subgraph "TSP Core Components"
        TSP[TSP Main Interface]
        Controller[Controller<br/>Configuration]
        Protocol[TSPProtocol<br/>Core Logic]
        Session[TSPProtocolSession<br/>Verification]
    end
    
    subgraph "Cryptographic Layer"
        Prime[Prime Generator]
        RNG[DeterministicRNG]
        Signature[Digital Signatures]
    end
    
    subgraph "Data Integrity"
        Merkle[Merkle Tree]
        Storage[commits.json]
    end
    
    TSP --> Controller
    TSP --> Protocol
    TSP --> Session
    
    Protocol --> Prime
    Protocol --> RNG
    Protocol --> Signature
    Protocol --> Merkle
    
    Session --> Storage
    Protocol --> Storage
    
    Storage -.->|Read| Session
```

## Use Case Examples

### Software Licensing Flow
```mermaid
graph LR
    V[Vendor] -->|Creates LICENSE| A[Artifact for Customer]
    A --> C[Customer]
    C -->|Verifies Ownership| S[Software Activated]
    C -->|Transfer License| T[New Customer]
    T -->|Creates Transfer Proof| N[New Artifact]
```

### Digital Certificate Flow  
```mermaid
graph LR
    U[University] -->|Issues CERTIFICATE| D[Diploma for Graduate]
    D --> G[Graduate]
    G -->|Shows to Employer| E[Employer Verifies]
    E -->|Independent Check| V[✅ Authentic]
```

### Web Authentication Flow
```mermaid
graph LR
    S[Server] -->|Creates WEB_AUTH| T[Session Token]
    T --> U[User Browser]
    U -->|Each Request| A[API Verification]
    A -->|Valid Token| R[Resource Access]
```

---

## Integration Points

Add these diagrams to your documentation:

1. **README.md** - Include the main workflow diagram
2. **Architecture documentation** - Component diagram
3. **API documentation** - Sequence diagrams
4. **Security documentation** - Verification flow
5. **Examples** - Use case specific flows

These visual guides will significantly improve adoption by making the protocol easier to understand and implement.