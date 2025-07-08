# Twilight Relayer SDK

A specialized Rust SDK for building relayer services on the Twilight blockchain ecosystem. This SDK provides comprehensive tools for managing trading operations, lending services, and smart contract interactions in a privacy-preserving environment.

## 🚀 Features

### Trading Operations
- **Leveraged Trading**: Create and settle leveraged trading positions
- **Order Management**: Handle trade order lifecycle and settlement


### Lending Services
- **Pool Management**: Manage lending pools and deposits
- **Settlement Operations**: Handle lending order settlements


### Advanced Features
- **Smart Contract Integration**: Full state management and proof generation
- **Zero-Knowledge Proofs**: Privacy-preserving transaction processing
- **Merkle Tree Operations**: Cryptographic proof generation and verification
- **Message Verification**: Client message validation and processing

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
twilight-relayer-sdk = { git = "https://github.com/twilight-project/twilight-relayer-sdk.git" }
```

## 🛠️ Quick Start

### Trading Operations

```rust
use twilight_relayer_sdk::order::*;

// Create a trading order
let tx = create_trade_order(
    input_coin,
    output_memo,
    signature,
    proof,
    &contract_manager,
    chain_network,
    fee,
)?;

// Broadcast the order
let tx_hash = broadcast_trade_order(tx)?;
```

### Lending Operations

```rust
use twilight_relayer_sdk::lend::*;

// Create a lending order
let tx = create_lend_order_transaction(
    input_coin,
    output_memo,
    input_state_output,
    output_state,
    signature,
    proof,
    &contract_manager,
    chain_network,
    fee,
    contract_owner_address,
    error,
    sk,
    pk,
)?;
```

## 🏗️ Architecture

### Core Modules

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `order` | Trading Operations | Order creation, settlement, liquidation |
| `lend` | Lending Services | Pool management, deposits, settlements |
| `relayer` | Core Services | Message handling, verification |
| `verify_client_message` | Validation | Client request validation |
| `signed_integer` | Utilities | Mathematical operations for finance |

### Supported Operations

- **Trading Orders**: Leveraged buy/sell orders with margin support
- **Order Settlement**: Automated settlement and profit/loss calculation
- **Lending Pools**: Deposit, withdrawal, and interest distribution
- **Liquidation**: Risk management and position liquidation
- **State Management**: Smart contract state tracking and updates

## 🔧 Configuration

### Environment Variables

```bash
# Required
export ZKOS_SERVER_URL="https://twilight.rest/zkos/"

# Optional
export DATABASE_URL="postgresql://username:password@localhost/relayer_db"
```

### Contract Programs

The SDK includes support for:
- CreateTraderOrder - Trading order creation
- SettleTraderOrder - Trade settlement
- CreateLendOrder - Lending order creation
- SettleLendOrder - Lending settlement
- LiquidateOrder - Position liquidation


## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test order
cargo test lend
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](.github/CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

**This library has not been formally audited and is not recommended for production use.**

This SDK is intended for experimental and testnet use only. It handles financial operations and cryptographic keys, so always:
- Test thoroughly in development environments
- Use secure key management practices
- Never use with mainnet funds without proper auditing
- Keep dependencies updated

## 🔗 Related Projects

- [Twilight Client SDK](https://github.com/twilight-project/twilight-client-sdk) - Client-side wallet SDK
- [Twilight Network](https://frontend.twilight.rest) - Main project website
- [zkos-rust](https://github.com/twilight-project/zkos-rust) - Core Zero Knowledge blockchain implementation

---

**Built for the Twilight ecosystem** 🌅
