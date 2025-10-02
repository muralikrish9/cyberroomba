# Contributing to CyberRoomba

Thank you for your interest in contributing to CyberRoomba! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

1. **Bug Reports**: Use the GitHub issue template
2. **Feature Requests**: Describe the feature and its use case
3. **Security Issues**: Please email security concerns directly

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** following our coding standards
4. **Add tests** if applicable
5. **Update documentation** as needed
6. **Submit a pull request**

## 📋 Development Setup

### Prerequisites

- Node.js 18+
- MongoDB
- Git
- Security tools (subfinder, httpx, nuclei)

### Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/cyberroomba.git
cd cyberroomba

# Install dependencies
npm install

# Build the project
npm run build

# Set up environment
cp env.example .env.local
# Edit .env.local with your configuration
```

## 🏗️ Project Architecture

### Core Components

- **CLI Modules** (`src/cli/`) - Command-line interfaces
- **Libraries** (`src/lib/`) - Core functionality
- **Schemas** (`src/schemas/`) - MongoDB data models
- **Modules** (`src/recon/`, `src/scope/`, `src/vuln/`) - Pipeline stages

### Key Principles

- **TypeScript First** - All code should be properly typed
- **Error Handling** - Comprehensive error handling and logging
- **Parallel Processing** - Optimize for performance
- **Security** - Input validation and sanitization
- **Documentation** - Code should be self-documenting

## 📝 Coding Standards

### TypeScript

- Use strict TypeScript configuration
- Define proper interfaces and types
- Avoid `any` types where possible
- Use async/await over Promises

### Code Style

- Use meaningful variable and function names
- Add JSDoc comments for public functions
- Follow existing code patterns
- Keep functions focused and small

### Error Handling

```typescript
// Good
try {
  const result = await riskyOperation();
  return result;
} catch (error) {
  console.error('Operation failed:', error.message);
  throw new Error(`Failed to perform operation: ${error.message}`);
}

// Bad
const result = await riskyOperation(); // No error handling
```

### Database Operations

```typescript
// Good - with proper error handling
async function saveResult(data: ResultData): Promise<void> {
  try {
    await db.collection('results').insertOne(data);
  } catch (error) {
    console.error('Database save failed:', error.message);
    throw error;
  }
}
```

## 🧪 Testing

### Test Structure

- Unit tests for individual functions
- Integration tests for database operations
- End-to-end tests for CLI commands

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## 📚 Documentation

### Code Documentation

- Use JSDoc for function documentation
- Include examples for complex functions
- Document all public APIs

### User Documentation

- Update README.md for new features
- Add setup instructions for new tools
- Document configuration options

## 🔒 Security Guidelines

### Input Validation

- Validate all user inputs
- Sanitize data before database operations
- Use parameterized queries

### API Keys

- Never commit API keys to version control
- Use environment variables for sensitive data
- Provide example configuration files

### Testing

- Only test against authorized targets
- Respect rate limits and terms of service
- Document security considerations

## 🚀 Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in package.json
- [ ] Security review completed

## 💬 Communication

### Discussion Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Pull Requests**: Code review and technical discussion

### Code Review Process

1. **Automated Checks**: CI/CD pipeline must pass
2. **Manual Review**: At least one maintainer review
3. **Testing**: Manual testing for new features
4. **Documentation**: Ensure documentation is updated

## 🎯 Areas for Contribution

### High Priority

- Additional bug bounty platform integrations
- Performance optimizations
- Enhanced error handling
- More attack templates

### Medium Priority

- Web dashboard
- API improvements
- Docker support
- CI/CD enhancements

### Low Priority

- Additional documentation
- Code refactoring
- Test coverage improvements
- UI/UX enhancements

## 📄 License

By contributing to CyberRoomba, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:

- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to CyberRoomba! 🚀
