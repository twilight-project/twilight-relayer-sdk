# Contributing to Twilight Client SDK

First off, thank you for considering contributing to the Twilight Client SDK! It's people like you that make Twilight an amazing platform. This document provides guidelines and steps for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct (we follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct)).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps which reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed after following the steps**
* **Explain which behavior you expected to see instead and why**
* **Include any relevant error messages and stack traces**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested enhancement**
* **Provide specific examples to demonstrate the steps**
* **Describe the current behavior and explain the behavior you expected to see instead**
* **Explain why this enhancement would be useful**

### Pull Requests

Please follow these steps to have your contribution considered by the maintainers:

1. Follow all instructions in the template
2. Follow the [styleguides](#styleguides)
3. After you submit your pull request, verify that all status checks are passing

#### Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable
2. Update the CHANGELOG.md with a note describing your changes
3. The PR will be merged once you have the sign-off of at least one other developer
4. If you haven't been granted permissions, the maintainers will merge it for you

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Rust Styleguide

* Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
* Use `rustfmt` for consistent code formatting
* Run `cargo clippy` and address all warnings
* Write documentation for all public items
* Include unit tests for new code
* Follow the existing code style

### Documentation Styleguide

* Use [Markdown](https://guides.github.com/features/mastering-markdown/)
* Reference functions, modules, and types in backticks
* Code blocks should specify the language:
    ```rust
    fn example() -> Result<(), Error> {
        // ...
    }
    ```

## Development Process

1. Fork the repo
2. Create a new branch from `develop`:
   ```bash
   git checkout -b feature/my-new-feature develop
   ```
3. Make your changes
4. Run the test suite:
   ```bash
   cargo test --all-features
   ```
5. Run the linter:
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```
6. Format your code:
   ```bash
   cargo fmt --all
   ```
7. Commit your changes
8. Push to your fork
9. Submit a Pull Request

## Setting Up Development Environment

1. Install Rust (stable) via [rustup](https://rustup.rs/)
2. Install development dependencies:
   ```bash
   rustup component add rustfmt
   rustup component add clippy
   ```
3. Clone the repository:
   ```bash
   git clone https://github.com/twilight-project/twilight-relayer-sdk.git
   cd twilight-relayer-sdk
   ```
4. Build the project:
   ```bash
   cargo build
   ```

## Running Tests

```bash
# Run all tests
cargo test --all-features

# Run specific tests
cargo test --package twilight-relayer-sdk --test order

# Run with logging
RUST_LOG=debug cargo test
```

## Additional Notes

### Issue and Pull Request Labels

| Label Name | Description |
|------------|-------------|
| `bug` | Confirmed bugs or reports that are very likely to be bugs |
| `enhancement` | Feature requests |
| `documentation` | Documentation improvements |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention is needed |
| `question` | Questions more than bug reports or feature requests |

## Recognition

Contributors who make significant and valuable contributions will be granted commit access to the project. These contributions include:

* Code contributions via pull requests
* Documentation improvements
* Bug reports and issue management
* Helping others in the community

## Questions?

Don't hesitate to reach out to the maintainers if you have any questions about contributing!

---

Thank you for contributing to Twilight Client SDK! 
