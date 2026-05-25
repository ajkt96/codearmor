# CODEARMOR: SAST/DAST Orchestration

Unified application security platform combining SAST and DAST scanning.

## Features

- SAST scanning with OWASP Top 10 detection
- - DAST scanning for runtime vulnerabilities
  - - Finding correlation and deduplication
    - - Automated remediation suggestions
      - - CI/CD pipeline integration
       
        - ## Quick Start
       
        - ```python
          from src.orchestrator import AppSecOrchestrator

          orch = AppSecOrchestrator()
          orch.run_sast("/app/src")
          orch.run_dast("https://app.example.com")
          report = orch.generate_report()
          ```

          ## License

          MIT License
          
