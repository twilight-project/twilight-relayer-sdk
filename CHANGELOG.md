# Changelog

All notable changes to the Twilight Relayer SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enhanced README documentation with example links and usage guides
- Environment variable support for configuration (TEST_SEED, ZKOS_SERVER_URL)
- Detailed logging with proper log levels throughout the codebase
- Extended test coverage for parameter validation and workflows
- CI/CD workflow with automated testing, formatting, and linting

### Changed
- Replaced hardcoded seeds with environment variable loading for better security
- Updated repository URL to reflect new GitHub organization structure
- Improved logging infrastructure replacing println! with proper log macros
- Enhanced documentation with clearer workflow explanations and usage patterns
- Refactored examples structure for better maintainability

### Security
- Removed hardcoded cryptographic seeds from source code
- Added security notices and warnings for production usage
- Improved environment variable handling for sensitive configuration

### Technical Improvements
- Code cleanup: removed unused imports and variables
- Better error handling and validation patterns
- Enhanced debugging capabilities with structured logging
- Expanded test suite with comprehensive parameter validation
- Improved code formatting and consistency

## [Previous Versions]

### Initial Release Features
- **Trading Operations**: Complete infrastructure for leveraged trading
  - Order creation with create_trade_order()
  - Order settlement with settle_trader_order()
  - Broadcasting capabilities with broadcast_trade_order()
  - Memo updating with update_trader_output_memo()

- **Lending Services**: Full lending pool management
  - Pool deposit handling with create_lend_order_transaction()
  - Settlement operations with create_lend_order_settlement_transaction()
  - State management with create_input_state_for_lend_order()
  - Memo updating with update_lender_output_memo()

- **Security & Verification**: Robust validation framework
  - Client message verification
  - Zero-knowledge proof generation and validation
  - Cryptographic signature handling
  - State witness management

- **Core Infrastructure**: Foundational components
  - Contract manager for program execution
  - Network abstraction layer
  - Transaction building and broadcasting
  - Merkle tree operations
  - Signed integer utilities

### Development Features
- Comprehensive test suite
- API documentation and examples
- Contract program templates

---

## Contributing to this Changelog

When adding entries:
- Include the scope of changes (module, feature, etc.)
- Link to relevant PRs or issues when available
- Follow the format: Category: Description (#PR)
- Group related changes together

---

**For the full history and detailed technical changes, see the [Git commit history](https://github.com/twilight-project/twilight-relayer-sdk/commits/main).** 