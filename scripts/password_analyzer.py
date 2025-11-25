#!/usr/bin/env python3
"""
🔐 Password Analyzer - Security Automation Tool

A comprehensive password security analyzer for ethical hackers.
Checks password strength, detects common passwords, and provides security recommendations.

Author: Rohith D
CEH Student | Aspiring Cybersecurity Professional
https://github.com/ROHITHD300900
"""

import re
import hashlib
import argparse
from typing import Dict, List, Tuple

# Terminal colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Common weak passwords list
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
    'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'football', 'shadow', 'passw0rd', 'admin', 'welcome'
]

def banner():
    print(f"""
{Colors.BLUE}╔═══════════════════════════════════════════════════════════════╗
║  🔐 Password Analyzer - Security Automation Tool              ║
║  Version: 1.0.0 | Author: Rohith D                             ║
║  For Educational Purposes Only                                 ║
╚═══════════════════════════════════════════════════════════════╝{Colors.END}
    """)

def check_length(password: str) -> Tuple[int, str]:
    """Check password length"""
    length = len(password)
    if length >= 16:
        return (3, f"{Colors.GREEN}Excellent{Colors.END} - {length} characters")
    elif length >= 12:
        return (2, f"{Colors.GREEN}Good{Colors.END} - {length} characters")
    elif length >= 8:
        return (1, f"{Colors.YELLOW}Fair{Colors.END} - {length} characters")
    else:
        return (0, f"{Colors.RED}Weak{Colors.END} - {length} characters")

def check_complexity(password: str) -> Dict[str, bool]:
    """Check password complexity"""
    return {
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'numbers': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }

def check_common(password: str) -> bool:
    """Check if password is commonly used"""
    return password.lower() in COMMON_PASSWORDS

def check_patterns(password: str) -> List[str]:
    """Check for weak patterns"""
    warnings = []
    
    if re.search(r'(.)\1{2,}', password):
        warnings.append("Contains repeated characters")
    if re.search(r'(012|123|234|345|456|567|678|789)', password):
        warnings.append("Contains sequential numbers")
    if re.search(r'(abc|bcd|cde|def|efg)', password.lower()):
        warnings.append("Contains sequential letters")
    if re.search(r'^[a-zA-Z]+$', password):
        warnings.append("Contains only letters")
    if re.search(r'^\d+$', password):
        warnings.append("Contains only numbers")
    
    return warnings

def calculate_score(password: str) -> int:
    """Calculate overall password strength score (0-100)"""
    score = 0
    
    # Length score (max 40)
    score += min(len(password) * 3, 40)
    
    # Complexity score (max 40)
    complexity = check_complexity(password)
    score += sum(10 for v in complexity.values() if v)
    
    # Pattern penalties
    warnings = check_patterns(password)
    score -= len(warnings) * 5
    
    # Common password penalty
    if check_common(password):
        score -= 30
    
    return max(0, min(100, score))

def get_hash(password: str) -> Dict[str, str]:
    """Generate common hashes of password"""
    return {
        'MD5': hashlib.md5(password.encode()).hexdigest(),
        'SHA-256': hashlib.sha256(password.encode()).hexdigest()
    }

def analyze_password(password: str) -> Dict:
    """Perform complete password analysis"""
    score = calculate_score(password)
    
    if score >= 80:
        strength = f"{Colors.GREEN}STRONG{Colors.END}"
    elif score >= 60:
        strength = f"{Colors.GREEN}GOOD{Colors.END}"
    elif score >= 40:
        strength = f"{Colors.YELLOW}MODERATE{Colors.END}"
    else:
        strength = f"{Colors.RED}WEAK{Colors.END}"
    
    return {
        'password_length': len(password),
        'score': score,
        'strength': strength,
        'complexity': check_complexity(password),
        'is_common': check_common(password),
        'warnings': check_patterns(password),
        'hashes': get_hash(password)
    }

def print_analysis(results: Dict):
    """Print analysis results"""
    print(f"\n{'='*60}")
    print(f"  PASSWORD ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"  Length: {results['password_length']} characters")
    print(f"  Score: {results['score']}/100")
    print(f"  Strength: {results['strength']}")
    
    print(f"\n  Complexity Check:")
    comp = results['complexity']
    print(f"    {'[+]' if comp['uppercase'] else '[-]'} Uppercase letters")
    print(f"    {'[+]' if comp['lowercase'] else '[-]'} Lowercase letters")
    print(f"    {'[+]' if comp['numbers'] else '[-]'} Numbers")
    print(f"    {'[+]' if comp['special'] else '[-]'} Special characters")
    
    if results['is_common']:
        print(f"\n  {Colors.RED}[!] WARNING: This is a commonly used password!{Colors.END}")
    
    if results['warnings']:
        print(f"\n  Warnings:")
        for w in results['warnings']:
            print(f"    {Colors.YELLOW}[!] {w}{Colors.END}")
    
    print(f"\n  Hash Values:")
    for algo, hash_val in results['hashes'].items():
        print(f"    {algo}: {hash_val}")
    
    print(f"{'='*60}\n")

def main():
    parser = argparse.ArgumentParser(description='Password Security Analyzer')
    parser.add_argument('-c', '--check', help='Password to analyze')
    parser.add_argument('-f', '--file', help='File with passwords to analyze')
    
    args = parser.parse_args()
    banner()
    
    if args.check:
        results = analyze_password(args.check)
        print_analysis(results)
    elif args.file:
        with open(args.file, 'r') as f:
            for line in f:
                password = line.strip()
                if password:
                    print(f"\nAnalyzing: {'*' * len(password)}")
                    results = analyze_password(password)
                    print_analysis(results)
    else:
        password = input("Enter password to analyze: ")
        results = analyze_password(password)
        print_analysis(results)

if __name__ == '__main__':
    main()
