#!/usr/bin/env python3
"""
simulate_attack.py
Run on the Attacker machine (192.168.56.102) to simulate a realistic
multi-stage attack against Server1 and trigger the profiling engine.

Stages:
  1. Reconnaissance - nmap SYN scan
  2. Directory enumeration - gobuster / manual HTTP probing
  3. Brute force SSH / HTTP login
  4. Decoy interaction (after redirect)
  5. Honeytoken access

Usage:
  python3 simulate_attack.py --target 192.168.56.103 --all
  python3 simulate_attack.py --target 192.168.56.103 --stage 1
  python3 simulate_attack.py --direct-inject --profiler 192.168.56.200
"""

import argparse
import subprocess
import time
import requests
import sys
import os

TARGET_SERVER1 = "192.168.56.103"
TARGET_DECOY   = "192.168.56.106"
PROFILER       = "192.168.56.200"
PROFILER_PORT  = 5000
API_KEY        = "deception-engine-secret-key-2024"


def banner(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print('='*60)


def run_cmd(cmd, description=""):
    """Run a shell command and print output."""
    print(f"\n[+] {description}")
    print(f"    $ {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            print(result.stdout[:500])
        if result.stderr:
            print(f"    STDERR: {result.stderr[:200]}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("    [!] Command timed out")
        return False
    except Exception as e:
        print(f"    [!] Error: {e}")
        return False


def inject_event(src_ip, event_type, severity, details, profiler=PROFILER):
    """Send a synthetic event directly to the profiler (for testing)."""
    url = f"http://{profiler}:{PROFILER_PORT}/api/event"
    payload = {
        "src_ip": src_ip,
        "event_type": event_type,
        "severity": severity,
        "details": details,
        "source": "simulation"
    }
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"    [PROFILER] Score: {data.get('previous_score'):.1f} -> "
                  f"{data.get('new_score'):.1f} | Status: {data.get('attacker_status')} "
                  f"| Actions: {data.get('actions_triggered')}")
            return data
        else:
            print(f"    [PROFILER] Error {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"    [PROFILER] Connection failed: {e}")
    return None


# ──────────────────────────── ATTACK STAGES ───────────────────────────────────

def stage1_reconnaissance(target):
    """
    Stage 1: Port scanning and reconnaissance.
    Expected score increase: ~13 points (syn_scan + port_sweep)
    """
    banner("STAGE 1: RECONNAISSANCE")
    print(f"Target: {target}")
    print("Tools: nmap")
    print("Expected score increase: ~13 points")

    # SYN Scan (requires root)
    run_cmd(
        f"nmap -sS -T4 -p 22,80,443,8080,3306,5432 {target}",
        "SYN scan (top ports)"
    )
    time.sleep(2)

    # Service version detection
    run_cmd(
        f"nmap -sV -T3 -p 22,80 {target}",
        "Service version detection"
    )
    time.sleep(2)

    # OS fingerprinting
    run_cmd(
        f"nmap -O {target} 2>/dev/null || echo 'OS scan requires root'",
        "OS fingerprinting"
    )
    print("\n[+] Stage 1 complete. Server monitor should have detected port scans.")


def stage2_enumeration(target):
    """
    Stage 2: Directory and file enumeration.
    Expected score increase: ~18 points (directory_enumeration x 3)
    """
    banner("STAGE 2: DIRECTORY ENUMERATION")
    print(f"Target: http://{target}/")
    print("Tools: gobuster, curl")
    print("Expected score increase: ~18 points")

    # gobuster directory scan
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/dirb/wordlists/common.txt"

    if os.path.exists(wordlist):
        run_cmd(
            f"gobuster dir -u http://{target}/ -w {wordlist} -t 10 -q 2>/dev/null | head -20",
            "gobuster directory enumeration"
        )
    else:
        print("    [!] gobuster wordlist not found. Simulating with curl probes.")
        # Manual HTTP probes to trigger detection
        paths = [
            "/admin", "/wp-admin", "/phpmyadmin", "/.env",
            "/config.php", "/backup", "/api", "/.git",
            "/database.sql", "/passwords.txt", "/secret-backup.zip"
        ]
        for path in paths:
            run_cmd(
                f"curl -s -o /dev/null -w '%{{http_code}} {path}\\n' http://{target}{path}",
                f"Probe {path}"
            )
            time.sleep(0.3)

    print("\n[+] Stage 2 complete. Multiple 404 probes should have been detected.")


def stage3_brute_force(target):
    """
    Stage 3: SSH and HTTP brute force.
    Expected score increase: ~30+ points (brute_force events)
    """
    banner("STAGE 3: BRUTE FORCE ATTACKS")
    print(f"Target: {target}")
    print("Tools: hydra")
    print("Expected score increase: ~30+ points")

    # SSH brute force (limited attempts to avoid lockout)
    run_cmd(
        f"hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 "
        f"-f {target} ssh -V 2>/dev/null | head -30 "
        f"|| echo 'hydra not installed or wordlist missing'",
        "SSH brute force with hydra"
    )
    time.sleep(2)

    # HTTP login brute force
    run_cmd(
        f"hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 "
        f"http-post-form '//admin/login:username=^USER^&password=^PASS^:Invalid' "
        f"{target} 2>/dev/null | head -20 "
        f"|| echo 'hydra HTTP brute force skipped'",
        "HTTP login brute force with hydra"
    )
    time.sleep(2)

    # curl rapid login attempts (triggers auth failure detection)
    print("\n[+] Sending rapid HTTP login attempts via curl:")
    for i in range(10):
        run_cmd(
            f"curl -s -X POST http://{target}/login "
            f"-d 'username=admin&password=wrong{i}' -o /dev/null -w '%{{http_code}}'",
            f"Login attempt {i+1}/10"
        )
        time.sleep(0.2)

    print("\n[+] Stage 3 complete. Brute force events should be at profiler.")


def stage4_decoy_interaction(target_decoy):
    """
    Stage 4: Interaction with decoy server (simulates post-redirect behavior).
    Expected score increase: ~10-35 points depending on honeytoken access
    """
    banner("STAGE 4: DECOY INTERACTION")
    print(f"Target (Decoy): http://{target_decoy}/")
    print("Simulating attacker exploring fake environment")

    # Probe decoy services
    paths = ["/", "/admin", "/phpmyadmin", "/api/shell"]
    for path in paths:
        run_cmd(
            f"curl -s -L http://{target_decoy}{path} -o /dev/null -w 'Status: %{{http_code}} Path: {path}\\n'",
            f"Decoy probe: {path}"
        )
        time.sleep(0.5)

    print("\n[+] Stage 4 complete. Decoy should have logged and reported interactions.")


def stage5_honeytoken_access(target):
    """
    Stage 5: Access honeytoken files (highest severity events).
    Expected score increase: ~50+ points (honeytoken_access x 2)
    """
    banner("STAGE 5: HONEYTOKEN ACCESS")
    print(f"Target: http://{target}/")
    print("Accessing fake sensitive files to trigger maximum alerts")

    honeytokens = [
        "/database-dump.sql",
        "/.env",
        "/passwords.txt",
        "/admin-credentials.json",
        "/secret-backup.zip",
    ]

    for path in honeytokens:
        result = run_cmd(
            f"curl -s http://{target}{path} | head -5",
            f"Accessing honeytoken: {path}"
        )
        time.sleep(1)

    print("\n[+] Stage 5 complete. Honeytoken events should trigger forensic snapshot!")


def direct_inject_simulation(attacker_ip, profiler):
    """
    Directly inject events into the profiler to simulate a full attack
    progression without needing actual attack tools.
    Perfect for demonstration without setting up attack tools.
    """
    banner("DIRECT INJECTION SIMULATION MODE")
    print(f"Injecting synthetic events for attacker IP: {attacker_ip}")
    print(f"Profiler: http://{profiler}:{PROFILER_PORT}")
    print()

    simulation_events = [
        # Stage 1: Reconnaissance
        ("syn_scan",    5,  "nmap SYN scan detected on port 22,80,443"),
        ("port_sweep",  8,  "nmap full port sweep T4"),
        # Stage 2: Enumeration
        ("directory_enumeration", 6, "gobuster dir scan /admin /config /.env"),
        ("directory_enumeration", 6, "Multiple 404 responses detected (12 probes)"),
        # Stage 3: Credential attacks
        ("failed_login",  3, "SSH failed password attempt #1"),
        ("failed_login",  3, "SSH failed password attempt #2"),
        ("failed_login",  3, "SSH failed password attempt #3"),
        ("brute_force",  15, "SSH brute force: 5+ failures from single IP"),
        # Stage 4: Decoy interaction
        ("decoy_interaction", 10, "Attacker reached decoy landing page"),
        ("fake_shell_command", 2, "Fake shell: whoami"),
        # Stage 5: Honeytoken access
        ("honeytoken_access", 25, "HONEYTOKEN: /database-dump.sql accessed"),
        ("honeytoken_access", 25, "HONEYTOKEN: /.env file accessed"),
        # Stage 6: Escalation
        ("privilege_escalation", 20, "Sudo command detected in session"),
    ]

    print(f"{'Event':<30} {'Weight':<8} {'Before':<10} {'After':<10} {'Status':<15} {'Actions'}")
    print("-" * 90)

    for event_type, severity, details in simulation_events:
        result = inject_event(attacker_ip, event_type, severity, details, profiler)
        if result:
            print(
                f"  {event_type:<28} {severity:<8} "
                f"{result.get('previous_score', 0):<10.1f} "
                f"{result.get('new_score', 0):<10.1f} "
                f"{result.get('attacker_status', ''):<15} "
                f"{result.get('actions_triggered', [])}"
            )
        time.sleep(0.5)

    print(f"\n[+] Simulation complete. Check dashboard at http://{profiler}:8080")


# ──────────────────────────── MAIN ────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Deception Engine Attack Simulator"
    )
    parser.add_argument("--target", default=TARGET_SERVER1, help="Target server IP")
    parser.add_argument("--decoy", default=TARGET_DECOY, help="Decoy server IP")
    parser.add_argument("--profiler", default=PROFILER, help="Profiler IP")
    parser.add_argument("--stage", type=int, choices=[1,2,3,4,5], help="Run single stage")
    parser.add_argument("--all", action="store_true", help="Run all stages sequentially")
    parser.add_argument("--direct-inject", action="store_true",
                        help="Inject events directly to profiler (no actual attacks)")
    parser.add_argument("--attacker-ip", default="192.168.56.102",
                        help="Spoofed attacker IP for direct injection")

    args = parser.parse_args()

    if args.direct_inject:
        direct_inject_simulation(args.attacker_ip, args.profiler)
        return

    if args.stage:
        stages = {
            1: lambda: stage1_reconnaissance(args.target),
            2: lambda: stage2_enumeration(args.target),
            3: lambda: stage3_brute_force(args.target),
            4: lambda: stage4_decoy_interaction(args.decoy),
            5: lambda: stage5_honeytoken_access(args.target),
        }
        stages[args.stage]()
        return

    if args.all:
        print(f"\nRunning full attack simulation against {args.target}")
        print("This simulates a realistic multi-stage attack progression.\n")
        stage1_reconnaissance(args.target)
        time.sleep(3)
        stage2_enumeration(args.target)
        time.sleep(3)
        stage3_brute_force(args.target)
        time.sleep(3)
        stage4_decoy_interaction(args.decoy)
        time.sleep(3)
        stage5_honeytoken_access(args.target)
        print(f"\n[DONE] Full simulation complete. Check dashboard at http://{args.profiler}:8080")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
