# Product Guidelines - PCAP Analyzer

## Documentation Style
- **Technical and Concise:** Documentation should be direct, accurate, and brief, catering to engineering tools.
- **Educational Context:** Provide context where relevant (e.g., RFC references, protocol explanations, security rationale) to aid understanding.
- **Code Comments:** Focus on the "why" rather than the "what". Docstrings should follow standard Python conventions with a brief summary followed by a detailed description when necessary.
- **Commit Messages:** Structured and direct (e.g., `FEATURE v4.25.0: ...`).
- **Structure:** well-organized code with clear imports and a technical, action-oriented README.

## Visual & Interaction Design
- **Clean and Data-Centric:** Prioritize data visualization, readability, and efficient workflow with a minimalist aesthetic.
- **Interactive Visualizations:** heavy emphasis on interactive charts using Plotly.js (Timeline graphs, protocol distribution, retransmission heatmaps).
- **Functional Workflow:** direct workflow (upload → analyze → visualize) with minimal friction for power users (max 3 clicks).
- **Persistent Reports:** HTML reports serve as the primary UI, focusing on data rather than chrome.
- **Target Audience:** Assume expert users (network engineers), avoiding heavy onboarding flows.

## Error Handling & Feedback
- **Secure and Generic:** Return generic error messages for authentication and security failures to avoid information leakage.
- **Context-Aware Redaction:** Sanitize error messages in production to remove PII and sensitive paths (e.g., `/home/user` -> `/home/[USER]`) while preserving system paths and diagnostic context.
- **Detailed Debugging (Dev Only):** Full stack traces are enabled only in Flask debug mode for development.
- **Sanitized Logs:** Production logs must be sanitized to strip credentials and sensitive internal details.

## Security Standards
- **High Assurance:** Strict compliance with OWASP Top 10 and CWE Top 25 mitigations.
- **Blocking Behavior:** Security violations (invalid uploads, CSRF, path traversal, auth failures) must strictly block the operation.
- **Defense in Depth:** Multiple layers of defense including strict input validation (magic numbers), CSRF protection, and RBAC.
- **Audit Logging:** Basic audit logging (Flask logs, database events) for debugging, distinct from a full compliance audit trail.
- **Testing:** Comprehensive test coverage for security modules is non-negotiable.
