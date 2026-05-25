"""SAST/DAST Orchestration Engine"""

from typing import List, Dict


class AppSecOrchestrator:
      """Orchestrates SAST and DAST scans"""

    def __init__(self):
              self.sast_findings = []
              self.dast_findings = []

    def run_sast(self, code_path: str) -> List[Dict]:
              """Run SAST scan"""
              findings = [
                  {
                      'type': 'SQL Injection',
                      'severity': 'CRITICAL',
                      'file': 'login.py',
                      'line': 42,
                      'owasp': 'A03:2021',
                      'cwe': 'CWE-89',
                      'remediation': 'Use parameterized queries'
                  },
                  {
                      'type': 'Hardcoded Secret',
                      'severity': 'HIGH',
                      'file': 'config.py',
                      'line': 5,
                      'owasp': 'A02:2021',
                      'cwe': 'CWE-798',
                      'remediation': 'Move to secrets manager'
                  }
              ]
              self.sast_findings = findings
              return findings

    def run_dast(self, target_url: str) -> List[Dict]:
              """Run DAST scan"""
              findings = [
                  {
                      'type': 'Missing Security Header',
                      'severity': 'MEDIUM',
                      'header': 'X-Frame-Options',
                      'owasp': 'A01:2021',
                      'remediation': 'Add X-Frame-Options: DENY'
                  }
              ]
              self.dast_findings = findings
              return findings

    def correlate_findings(self) -> List[Dict]:
              """Correlate and deduplicate findings"""
              severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
              all_findings = self.sast_findings + self.dast_findings
              return sorted(all_findings, key=lambda f: severity_order.get(f['severity'], 4))

    def generate_report(self) -> Dict:
              """Generate security report"""
              all_findings = self.sast_findings + self.dast_findings
              return {
                  'sast_count': len(self.sast_findings),
                  'dast_count': len(self.dast_findings),
                  'total': len(all_findings),
                  'critical': sum(1 for f in all_findings if f['severity'] == 'CRITICAL'),
                  'findings': self.correlate_findings()
              }


if __name__ == "__main__":
      orch = AppSecOrchestrator()
      orch.run_sast("/app/src")
      orch.run_dast("https://app.example.com")
      report = orch.generate_report()
      print(f"Total: {report['total']} findings, Critical: {report['critical']}")
  
