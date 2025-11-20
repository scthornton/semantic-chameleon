# Security Policy

## Defensive Research Commitment

This repository contains **defensive security research only**. All materials are designed to help organizations understand and defend against RAG poisoning attacks. No weaponizable attack implementations are included.

---

## What IS Included (Safe for Public Release)

✅ **Detection Methods**
- 5 detection algorithm implementations
- Evaluation metrics and statistical tests
- ROC curve generation and analysis
- Corpus-specific detection guidance

✅ **Defense Mechanisms**
- Hybrid BM25+vector retrieval implementation
- Deployment configuration recommendations
- Security assessment tools
- Monitoring and alerting strategies

✅ **Educational Materials**
- Sanitized attack scenario descriptions
- Conceptual understanding of attack patterns
- Corpus analysis and security properties
- Best practices for RAG system hardening

✅ **Evaluation Tools**
- Statistical significance testing
- Confidence interval computation
- Performance benchmarking
- Corpus property analysis

---

## What is NOT Included (Removed for Safety)

❌ **Attack Implementations**
- No working gradient optimization code
- No adversarial document generation
- No token-level manipulation strategies
- No embedding attack techniques

❌ **Weaponizable Content**
- No complete malicious queries
- No actual poisoned document text
- No attack automation pipelines
- No exploitation tools

❌ **Sensitive Details**
- Attack-specific hyperparameters redacted
- Optimization strategies sanitized
- Specific attack scenarios neutered
- Vulnerability details minimized

---

## Responsible Disclosure

If you discover vulnerabilities in RAG systems during defensive research:

### For Researchers

1. **Do NOT** publicly disclose vulnerabilities before coordination
2. **DO** contact affected vendors privately
3. **DO** allow reasonable time for fixes (typically 90 days)
4. **DO** document your findings professionally
5. **DO** follow coordinated disclosure best practices

### For Vendors

If you believe this research affects your product:

1. Contact us at: [your-security-email]
2. We will work with you on coordinated disclosure
3. We can provide additional technical details under NDA
4. We support responsible 90-day disclosure timelines

---

## Reporting Security Issues

### In This Repository

If you find security issues in THIS repository's code:

**Contact**: [your-email]
**PGP Key**: [Optional - add if you have one]

**Please include**:
- Description of the issue
- Steps to reproduce
- Potential impact assessment
- Suggested mitigations (if any)

**Response Timeline**:
- Initial acknowledgment: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity (typically 30 days for high severity)

### In RAG Systems (General)

If you discover vulnerabilities in production RAG systems:

1. **Identify the vendor** - Determine who operates the system
2. **Find security contact** - Check vendor's security.txt or security page
3. **Report privately** - Do NOT post on social media or public forums
4. **Provide details** - Include reproduction steps and impact assessment
5. **Allow response time** - Give vendors 90 days to patch before disclosure

---

## Ethical Use Guidelines

### Permitted Uses

✅ **Defensive Research**
- Testing your own RAG systems
- Academic security research
- Red team exercises (with authorization)
- Security tool development
- Training and education

✅ **Security Improvement**
- Implementing detection methods
- Deploying defensive architectures
- Monitoring RAG system security
- Incident response preparation
- Security assessment of owned systems

### Prohibited Uses

❌ **Offensive Activities**
- Attacking systems you don't own
- Unauthorized security testing
- Malicious corpus poisoning
- Data exfiltration attempts
- System disruption or sabotage

❌ **Weaponization**
- Creating attack tools for distribution
- Developing automated attack frameworks
- Selling attack services
- Teaching attack techniques without defense context
- Sharing attack materials irresponsibly

---

## Academic and Industry Collaboration

We welcome collaboration with:

- **Academic Researchers**: For extending defenses and understanding attack patterns
- **Security Vendors**: For integrating detection methods into products
- **RAG Operators**: For hardening production deployments
- **Standards Bodies**: For developing RAG security guidelines

**Contact for collaboration**: [your-email]

### Information Sharing

For legitimate defensive research requiring additional details:

1. Provide **institutional verification** (academic email, company security contact)
2. Explain **defensive use case** (what defenses you're building)
3. Agree to **responsible use** (no weaponization, coordinated disclosure)

We may share additional technical details under these conditions.

---

## Vulnerability Disclosure Policy

This research follows industry-standard coordinated disclosure:

**Timeline**:
- Day 0: Vulnerability discovered and verified
- Day 1-7: Vendor notification with technical details
- Day 7-90: Vendor develops and tests patch
- Day 90: Public disclosure (or earlier if patch is released)
- Day 90+: Full technical details and tools released

**Exceptions**:
- Active exploitation → immediate limited disclosure
- Vendor unresponsive → disclosure after 90 days regardless
- Vendor requests extension → negotiate case-by-case (max 120 days)

---

## Security Maturity of This Code

**Current Status**: Research Prototype

**Security Level**:
- ✅ Detection methods: Production-ready concepts
- ✅ Defense mechanisms: Production-ready implementations
- ⚠️ Evaluation tools: Research-grade, not hardened
- ⚠️ Example code: Educational, requires adaptation

**Before Production Use**:
1. Review code for your specific environment
2. Add input validation and error handling
3. Implement rate limiting and resource controls
4. Add logging and monitoring
5. Conduct security review

---

## Legal and Compliance

### License

This repository is licensed under MIT License with **Responsible Use Clause**:

> By using this code, you agree to use it only for defensive security research,
> system hardening, and educational purposes. Malicious use is prohibited and
> violates the terms of this license.

### Compliance

This research complies with:
- ✅ CFAA (Computer Fraud and Abuse Act) - Authorized testing only
- ✅ DMCA Section 1201 - Security research exemption
- ✅ EU Cybersecurity Act - Vulnerability disclosure provisions
- ✅ Academic ethics guidelines - IRB approval not required (no human subjects)

### Export Control

**ECCN Classification**: Not subject to EAR (educational materials, publicly available)

This research is published openly and does not contain:
- Encryption beyond publicly available standards
- Military-specific technology
- Controlled technical data

---

## Updates and Maintenance

**Security Updates**: We will patch security issues in this repository
**Research Updates**: New detection methods and defenses will be added
**Deprecation Notice**: We will announce if research becomes outdated

**Subscribe for updates**: [GitHub watch / email list]

---

## Contact

**Primary Contact**: Scott Thornton
**Email**: [your-email]

**Response Times**:
- Security issues: Within 48 hours
- Collaboration inquiries: Within 7 days
- General questions: Best effort

---

## Acknowledgments

We thank the security research community for responsible disclosure practices and collaborative defense development.

**Report security issues responsibly. Help us keep RAG systems secure.**

---

*Last Updated: November 2025*
*Next Review: February 2026*
