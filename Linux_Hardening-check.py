#!/usr/bin/env python3
"""
Linux Hardening Compliance Checker
Checks common security configurations against hardening benchmarks
"""

import os
import re
import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path

class LinuxComplianceChecker:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'checks': {}
        }
        
    def run_command(self, cmd):
        """Execute shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "Command timed out", 1
        except Exception as e:
            return str(e), 1

    def check_password_policy(self):
        """Check password policy compliance"""
        checks = {}
        
        # Check password aging
        output, _ = self.run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")
        if output:
            max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', output)
            if max_days:
                checks['password_max_days'] = {
                    'value': int(max_days.group(1)),
                    'compliant': int(max_days.group(1)) <= 90,
                    'expected': '<= 90 days'
                }
        
        # Check minimum password length
        output, _ = self.run_command("grep '^PASS_MIN_LEN' /etc/login.defs")
        if output:
            min_len = re.search(r'PASS_MIN_LEN\s+(\d+)', output)
            if min_len:
                checks['password_min_length'] = {
                    'value': int(min_len.group(1)),
                    'compliant': int(min_len.group(1)) >= 12,
                    'expected': '>= 12 characters'
                }
        
        # Check pam password quality
        output, _ = self.run_command("grep 'pam_pwquality.so' /etc/pam.d/common-password")
        checks['pam_pwquality'] = {
            'value': 'Found' if output else 'Not found',
            'compliant': bool(output),
            'expected': 'pam_pwquality.so configured'
        }
        
        self.results['checks']['password_policy'] = checks

    def check_ssh_config(self):
        """Check SSH server configuration"""
        checks = {}
        ssh_config = '/etc/ssh/sshd_config'
        
        if os.path.exists(ssh_config):
            with open(ssh_config, 'r') as f:
                content = f.read()
            
            # Check Protocol version
            protocol_match = re.search(r'^Protocol\s+(\d+)', content, re.MULTILINE)
            checks['ssh_protocol'] = {
                'value': protocol_match.group(1) if protocol_match else 'Not set',
                'compliant': protocol_match and int(protocol_match.group(1)) >= 2,
                'expected': 'Protocol 2'
            }
            
            # Check PermitRootLogin
            root_login_match = re.search(r'^PermitRootLogin\s+(.+)', content, re.MULTILINE)
            checks['permit_root_login'] = {
                'value': root_login_match.group(1) if root_login_match else 'Not set',
                'compliant': root_login_match and root_login_match.group(1).lower() in ['no', 'prohibit-password'],
                'expected': 'no or prohibit-password'
            }
            
            # Check PasswordAuthentication
            password_auth_match = re.search(r'^PasswordAuthentication\s+(.+)', content, re.MULTILINE)
            checks['password_authentication'] = {
                'value': password_auth_match.group(1) if password_auth_match else 'Not set',
                'compliant': password_auth_match and password_auth_match.group(1).lower() == 'no',
                'expected': 'no'
            }
        
        self.results['checks']['ssh_config'] = checks

    def check_file_permissions(self):
        """Check critical file permissions"""
        checks = {}
        critical_files = {
            '/etc/passwd': '644',
            '/etc/shadow': '640',
            '/etc/gshadow': '640',
            '/etc/group': '644',
            '/etc/sudoers': '440'
        }
        
        for file_path, expected_perm in critical_files.items():
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                actual_perm = oct(stat_info.st_mode)[-3:]
                checks[file_path] = {
                    'value': actual_perm,
                    'compliant': actual_perm == expected_perm,
                    'expected': expected_perm
                }
        
        self.results['checks']['file_permissions'] = checks

    def check_firewall_status(self):
        """Check firewall status"""
        checks = {}
        
        # Check UFW status
        output, code = self.run_command("ufw status")
        checks['ufw_status'] = {
            'value': 'Active' if 'Status: active' in output else 'Inactive',
            'compliant': 'Status: active' in output,
            'expected': 'Active'
        }
        
        # Check iptables has rules
        output, _ = self.run_command("iptables -L -n")
        checks['iptables_rules'] = {
            'value': 'Has rules' if output and 'Chain' in output else 'No rules or not installed',
            'compliant': bool(output and 'Chain' in output and 'policy DROP' in output),
            'expected': 'Firewall rules configured'
        }
        
        self.results['checks']['firewall'] = checks

    def check_audit_logging(self):
        """Check audit and logging configuration"""
        checks = {}
        
        # Check auditd service
        output, _ = self.run_command("systemctl is-active auditd")
        checks['auditd_status'] = {
            'value': output,
            'compliant': output == 'active',
            'expected': 'active'
        }
        
        # Check rsyslog service
        output, _ = self.run_command("systemctl is-active rsyslog")
        checks['rsyslog_status'] = {
            'value': output,
            'compliant': output == 'active',
            'expected': 'active'
        }
        
        self.results['checks']['logging'] = checks

    def check_system_updates(self):
        """Check system update status"""
        checks = {}
        
        # Check if updates are available (Ubuntu/Debian)
        output, _ = self.run_command("apt list --upgradable")
        updates_available = len([line for line in output.split('\n') if line.startswith(' Listing...') is False and line.strip()])
        
        checks['security_updates'] = {
            'value': f"{updates_available} packages need updates",
            'compliant': updates_available == 0,
            'expected': 'All packages updated'
        }
        
        # Check automatic updates
        output, _ = self.run_command("systemctl is-active unattended-upgrades")
        checks['auto_updates'] = {
            'value': output,
            'compliant': output == 'active',
            'expected': 'active'
        }
        
        self.results['checks']['updates'] = checks

    def generate_report(self):
        """Generate compliance report"""
        total_checks = 0
        compliant_checks = 0
        
        print("\n" + "="*60)
        print("LINUX HARDENING COMPLIANCE REPORT")
        print("="*60)
        print(f"Hostname: {self.results['hostname']}")
        print(f"Timestamp: {self.results['timestamp']}")
        print("="*60)
        
        for category, checks in self.results['checks'].items():
            print(f"\n{category.upper().replace('_', ' ')}:")
            print("-" * 40)
            
            for check_name, check_data in checks.items():
                total_checks += 1
                status = "✓ COMPLIANT" if check_data['compliant'] else "✗ NON-COMPLIANT"
                if check_data['compliant']:
                    compliant_checks += 1
                
                print(f"{status}: {check_name}")
                print(f"    Current: {check_data['value']}")
                print(f"    Expected: {check_data['expected']}")
        
        print("\n" + "="*60)
        compliance_percentage = (compliant_checks / total_checks) * 100 if total_checks > 0 else 0
        print(f"OVERALL COMPLIANCE: {compliance_percentage:.1f}% ({compliant_checks}/{total_checks} checks)")
        print("="*60)
        
        # Save detailed results to JSON
        with open(f"compliance_report_{self.results['hostname']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
            json.dump(self.results, f, indent=2)

    def run_all_checks(self):
        """Execute all compliance checks"""
        print("Running Linux hardening compliance checks...")
        self.check_password_policy()
        self.check_ssh_config()
        self.check_file_permissions()
        self.check_firewall_status()
        self.check_audit_logging()
        self.check_system_updates()
        self.generate_report()

def main():
    """Main function"""
    if os.geteuid() != 0:
        print("Warning: Some checks may require root privileges for accurate results.")
        print("Consider running with sudo for full compliance checking.\n")
    
    checker = LinuxComplianceChecker()
    checker.run_all_checks()

if __name__ == "__main__":
    main()
