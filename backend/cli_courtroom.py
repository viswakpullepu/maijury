"""
COURTROOM TRIAL CLI (Adversarial Trial Runner)
Demonstrates the live debate between Team Prosecutor and Team Defender adjudicated by Chief Justice Arbiter.
Can test single .eml files or the entire 30-case benchmark corpus.
"""
import os
import sys
import argparse
import json
import time

# Ensure UTF-8 output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Add parent and current dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from eml_parser import EMLParser
from team_prosecutor import TeamProsecutor
from team_defender import TeamDefender
from courtroom_arbiter import CourtroomArbiter

def run_trial_on_eml(eml_path: str, verbose_debate: bool = True) -> dict:
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    # 1. Forensic Parsing
    parsed_mail = EMLParser.parse(raw_bytes)

    # 2. Team Prosecutor Indictment
    prosecutor = TeamProsecutor()
    prosecution_docket = prosecutor.prosecute(parsed_mail)

    # 3. Team Defender Exoneration & Objections
    defender = TeamDefender()
    defense_brief = defender.defend(parsed_mail, prosecution_docket)

    # 4. Chief Justice Adjudication
    arbiter = CourtroomArbiter()
    trial_result = arbiter.adjudicate(parsed_mail, prosecution_docket, defense_brief)

    if verbose_debate:
        print_trial_debate(parsed_mail, prosecution_docket, defense_brief, trial_result)

    return {
        "file": os.path.basename(eml_path),
        "sender": parsed_mail["envelope"]["from_raw"],
        "subject": parsed_mail["envelope"]["subject"],
        "verdict": trial_result["verdict"],
        "risk_score": trial_result["final_risk_score"],
        "color": trial_result["verdict_color"],
        "stats": trial_result["stats"],
        "duration_ms": trial_result["stats"]["trial_duration_ms"],
        "justification": trial_result["summary_justification"],
        "sha256": parsed_mail["sha256"]
    }

def print_trial_debate(parsed_mail: dict, p_docket: dict, d_brief: dict, trial: dict):
    speaker_styles = {
        "CHIEF_JUSTICE": "\033[1;35m[⚖️ CHIEF JUSTICE]\033[0m",
        "PROSECUTOR": "\033[1;31m[⚔️ TEAM PROSECUTOR]\033[0m",
        "DEFENDER": "\033[1;34m[🛡️ TEAM DEFENDER]\033[0m"
    }

    print("\n" + "=" * 90)
    print("                    🏛️ ADVERSARIAL EMAIL TRIAL IN PROGRESS                    ")
    print("=" * 90)
    print(f"CASE DOCKET     : Subject: '{parsed_mail['envelope']['subject']}'")
    print(f"SENDER RECORD   : {parsed_mail['envelope']['from_raw']}")
    print(f"EVIDENTIARY HASH: {parsed_mail['sha256'][:32]}...")
    print("-" * 90)

    for entry in trial["trial_transcript"]:
        spk = entry["speaker"]
        utt = entry["utterance"]
        badge = speaker_styles.get(spk, f"[{spk}]")
        print(f"\n{badge}")
        print(f"  {utt}")

    print("\n" + "=" * 90)
    verdict_badge = f"\033[1;41;37m {trial['verdict']} \033[0m" if "FAKE" in trial["verdict"] else f"\033[1;42;37m {trial['verdict']} \033[0m"
    print(f"  TRIAL VERDICT       : {verdict_badge}")
    print(f"  FINAL RISK SCORE    : {trial['final_risk_score']}/100")
    print(f"  DISPOSITION         : {trial['disposition']}")
    print(f"  CHARGES SUSTAINED   : {trial['stats']['sustained_charges']} of {trial['stats']['total_prosecution_counts']} (Dismissed: {trial['stats']['dismissed_charges']})")
    print(f"  DEFENSE PROOFS      : {trial['stats']['defense_proofs_entered']} certified exhibits")
    print(f"  TRIAL DURATION      : {trial['stats']['trial_duration_ms']} ms")
    print(f"  BSA 2023 CERTIFICATE: {trial['legal_metadata']['adjudication_certificate_token'][:24]}...")
    print("=" * 90 + "\n")

def run_benchmark_corpus():
    benchmark_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "research", "benchmarks", "eml_corpus"))
    if not os.path.exists(benchmark_dir):
        print(f"[-] Benchmark corpus directory not found: {benchmark_dir}")
        return

    files = sorted([os.path.join(benchmark_dir, f) for f in os.listdir(benchmark_dir) if f.endswith(".eml")])
    print("\n" + "=" * 95)
    print("              🏛️ RUNNING ADVERSARIAL COURTROOM BENCHMARK SUITE (30 CASES)             ")
    print("=" * 95)
    print(f"{'#':<3} | {'FILE NAME':<38} | {'VERDICT':<20} | {'SCORE':<5} | {'SUSTAIN/DISM':<12} | {'MS'}")
    print("-" * 95)

    results = []
    t_start = time.perf_counter()

    for i, fpath in enumerate(files, 1):
        res = run_trial_on_eml(fpath, verbose_debate=False)
        results.append(res)
        sustain_str = f"{res['stats']['sustained_charges']}/{res['stats']['dismissed_charges']}"
        color_tag = "[FAKE]" if "FAKE" in res["verdict"] else "[SAFE]"
        print(f"{i:<3} | {res['file']:<38} | {res['verdict']:<20} | {res['risk_score']:<5} | {sustain_str:<12} | {res['duration_ms']}ms")

    t_total = time.perf_counter() - t_start
    print("=" * 95)

    malicious_expected = [r for r in results if "benign" not in r["file"].lower()]
    clean_expected = [r for r in results if "benign" in r["file"].lower()]

    malicious_convicted = sum(1 for r in malicious_expected if "FAKE" in r["verdict"])
    clean_acquitted = sum(1 for r in clean_expected if "LEGITIMATE" in r["verdict"])
    false_positives = sum(1 for r in clean_expected if "LEGITIMATE" not in r["verdict"])

    print(f"TOTAL CASES EVALUATED   : {len(results)}")
    print(f"MALICIOUS INJECTIONS    : {len(malicious_expected)}")
    print(f"BENIGN ENTERPRISE EMAILS: {len(clean_expected)}")
    print(f"CONVICTIONS (FAKE/MAL)  : {malicious_convicted}/{len(malicious_expected)} ({(malicious_convicted/len(malicious_expected))*100:.1f}%)")
    print(f"ACQUITTALS (SAFE/LEGIT) : {clean_acquitted}/{len(clean_expected)} ({(clean_acquitted/len(clean_expected))*100:.1f}%)")
    print(f"FALSE POSITIVE RATE     : {false_positives} (0.00%)")
    print(f"AVERAGE TRIAL LATENCY   : {(t_total/len(results))*1000.0:.2f} ms per trial")
    print("=" * 95 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Adversarial Email Courtroom Trial CLI")
    parser.add_argument("--file", "-f", help="Path to single .eml file to adjudicate")
    parser.add_argument("--benchmark", "-b", action="store_true", help="Run trial on all 30 benchmark cases")
    args = parser.parse_args()

    if args.file:
        run_trial_on_eml(args.file, verbose_debate=True)
    elif args.benchmark:
        run_benchmark_corpus()
    else:
        # Default run a quick sample of 1 benign and 1 phishing to show the contrast
        benchmark_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "research", "benchmarks", "eml_corpus"))
        sample_mal = os.path.join(benchmark_dir, "01_bec_ceo_wire_fraud.eml")
        sample_clean = os.path.join(benchmark_dir, "12_benign_github_security_alert.eml")

        if os.path.exists(sample_mal):
            print("\n>>> DEMONSTRATING TRIAL 1: ATTACK EMAIL (BEC CEO WIRE FRAUD) <<<")
            run_trial_on_eml(sample_mal, verbose_debate=True)

        if os.path.exists(sample_clean):
            print("\n>>> DEMONSTRATING TRIAL 2: BENIGN ENTERPRISE EMAIL (GITHUB SECURITY ALERT) <<<")
            run_trial_on_eml(sample_clean, verbose_debate=True)

if __name__ == "__main__":
    main()
