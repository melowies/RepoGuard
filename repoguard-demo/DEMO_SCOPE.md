# RepoGuard Demo Scope

Presentation date: 6 May

Decision:
- No live GitHub API.
- No internet dependency.
- Demo uses two local folders:
  1. vulnerable-demo-repo
  2. secure-demo-repo

Demo flow:
1. Scan vulnerable-demo-repo -> expected BLOCKED.
2. Show findings: secrets, risky dependencies, risky CI/CD, invalid signature.
3. Scan secure-demo-repo -> expected APPROVED.
4. Run attack simulator -> tamper release file.
5. Re-scan -> hash mismatch + invalid signature + BLOCKED.

Important:
- All secrets are fake demo values.
- Real API keys/passwords must not be used.
- Private key is included only in signing_keys_DEMO_ONLY for educational demo setup.
