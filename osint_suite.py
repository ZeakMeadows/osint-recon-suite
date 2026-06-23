#!/usr/bin/env python3
"""
OSINT Recon Suite
Author: Zeak Meadows
Description: Automated OSINT framework for digital footprinting and threat intelligence
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch


class OSINTReconSuite:
    def __init__(self, target, target_type, check_breaches=False, deep=False):
        self.target = target
        self.target_type = target_type
        self.check_breaches = check_breaches
        self.deep = deep
        self.results = {
            "target": target,
            "type": target_type,
            "timestamp": datetime.now().isoformat(),
            "findings": {}
        }
    
    def run_sherlock(self):
        """Run Sherlock for username enumeration"""
        print(f"[*] Running Sherlock on: {self.target}")
        try:
            result = subprocess.run(
                ["sherlock", self.target, "--json", "sherlock_output.json"],
                capture_output=True, text=True, timeout=300
            )
            time.sleep(2)
            
            output_file = Path("sherlock_output.json")
            if output_file.exists():
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    self.results["findings"]["sherlock"] = {
                        "platforms_found": len(data),
                        "accounts": data
                    }
                output_file.unlink()
                print(f"[+] Found {len(data)} potential accounts")
            else:
                self.results["findings"]["sherlock"] = {"error": "No results found"}
                
        except Exception as e:
            self.results["findings"]["sherlock"] = {"error": str(e)}
            print(f"[-] Sherlock error: {e}")
    
    def run_holehe(self):
        """Run Holehe for email OSINT"""
        print(f"[*] Running Holehe on: {self.target}")
        try:
            result = subprocess.run(
                ["holehe", self.target],
                capture_output=True, text=True, timeout=300
            )
            
            lines = result.stdout.split('\n')
            accounts = []
            for line in lines:
                if "[+]" in line and "@" in line:
                    accounts.append(line.strip())
            
            self.results["findings"]["holehe"] = {
                "accounts_found": len(accounts),
                "details": accounts
            }
            print(f"[+] Found {len(accounts)} associated accounts")
            
        except Exception as e:
            self.results["findings"]["holehe"] = {"error": str(e)}
            print(f"[-] Holehe error: {e}")
    
    def check_breaches(self):
        """Check Have I Been Pwned for email breaches"""
        if not self.check_breaches or self.target_type != "email":
            return
        
        print(f"[*] Checking breaches for: {self.target}")
        try:
            headers = {"User-Agent": "OSINT-Recon-Suite"}
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.target}"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                self.results["findings"]["breaches"] = {
                    "breached": True,
                    "breach_count": len(breaches),
                    "breaches": [b["Name"] for b in breaches]
                }
                print(f"[!] Found in {len(breaches)} breaches!")
            elif response.status_code == 404:
                self.results["findings"]["breaches"] = {"breached": False}
                print("[+] No breaches found")
            else:
                self.results["findings"]["breaches"] = {
                    "error": f"API returned {response.status_code}"
                }
                
        except Exception as e:
            self.results["findings"]["breaches"] = {"error": str(e)}
            print(f"[-] Breach check error: {e}")
    
    def run_theharvester(self):
        """Run theHarvester for domain reconnaissance"""
        if self.target_type != "domain":
            return
        
        print(f"[*] Running theHarvester on: {self.target}")
        try:
            result = subprocess.run(
                ["python3", "theHarvester/theHarvester.py", 
                 "-d", self.target, "-b", "all", "-f", "harvester_output"],
                capture_output=True, text=True, timeout=600
            )
            
            output_file = Path(f"harvester_output.xml")
            if output_file.exists():
                self.results["findings"]["theharvester"] = {
                    "status": "completed",
                    "output_file": str(output_file)
                }
                print("[+] Domain reconnaissance completed")
            else:
                self.results["findings"]["theharvester"] = {
                    "emails": [],
                    "hosts": [],
                    "note": "Run theHarvester manually for full output"
                }
                
        except Exception as e:
            self.results["findings"]["theharvester"] = {"error": str(e)}
            print(f"[-] theHarvester error: {e}")
    
    def generate_report(self, output_file="osint_report.pdf"):
        """Generate PDF report of findings"""
        print(f"[*] Generating report: {output_file}")
        
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a2e')
        )
        story.append(Paragraph("OSINT Reconnaissance Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        meta_data = [
            ["Target:", self.target],
            ["Investigation Type:", self.target_type.upper()],
            ["Timestamp:", self.results["timestamp"]],
            ["Analyst:", "Zeak Meadows"],
            ["Framework:", "OSINT Recon Suite v1.0"]
        ]
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("Findings Summary", styles['Heading2']))
        
        for tool, findings in self.results["findings"].items():
            story.append(Paragraph(f"<b>{tool.upper()}</b>", styles['Heading3']))
            if isinstance(findings, dict):
                for key, value in findings.items():
                    story.append(Paragraph(f"• {key}: {value}", styles['BodyText']))
            else:
                story.append(Paragraph(str(findings), styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.3*inch))
        disclaimer = Paragraph(
            "<i>This report is for authorized security assessments only. "
            "All findings should be verified through additional sources.</i>",
            styles['Italic']
        )
        story.append(disclaimer)
        
        doc.build(story)
        print(f"[+] Report saved: {output_file}")
        return output_file
    
    def run(self):
        """Execute full reconnaissance pipeline"""
        print(f"\n{'='*60}")
        print(f"  OSINT RECONNAISSANCE SUITE v1.0")
        print(f"  Target: {self.target}")
        print(f"{'='*60}\n")
        
        if self.target_type == "username":
            self.run_sherlock()
        elif self.target_type == "email":
            self.run_holehe()
            self.check_breaches()
        elif self.target_type == "domain":
            self.run_theharvester()
        
        json_file = f"results_{self.target.replace('@', '_at_').replace('.', '_')}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Raw results saved: {json_file}")
        
        return self.results


def main():
    parser = argparse.ArgumentParser(description='OSINT Reconnaissance Suite')
    parser.add_argument('--target', required=True, help='Target username, email, or domain')
    parser.add_argument('--type', choices=['username', 'email', 'domain'], required=True,
                        help='Type of investigation')
    parser.add_argument('--check-breaches', action='store_true', 
                        help='Check Have I Been Pwned (email only)')
    parser.add_argument('--deep', action='store_true', 
                        help='Enable deep reconnaissance')
    parser.add_argument('--output', default='osint_report.pdf', 
                        help='Output PDF report filename')
    
    args = parser.parse_args()
    
    suite = OSINTReconSuite(
        target=args.target,
        target_type=args.type,
        check_breaches=args.check_breaches,
        deep=args.deep
    )
    
    results = suite.run()
    suite.generate_report(args.output)
    
    print(f"\n{'='*60}")
    print("  INVESTIGATION COMPLETE")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
