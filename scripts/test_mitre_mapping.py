import os
import sys
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
sys.stdout.reconfigure(encoding='utf-8')

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url=os.getenv("OPENAI_BASE_URL", "https://api.groq.com/openai/v1"),
)

system_prompt = """You are Cypher AI, an expert MITRE ATT&CK cybersecurity intelligence engine.
Your purpose is to map and categorize threat queries strictly within the MITRE ATT&CK framework.
Do NOT give generic or textbook advice.

Format your response strictly using this MITRE ATT&CK Intelligence Mapping template:

### 1. MITRE Tactic Stage
- **Tactic**: [e.g. TA0006: Credential Access]
- **Adversary Objective**: [1-2 sentences on why the adversary executes this phase]

### 2. Mapped MITRE Techniques & Sub-Techniques
- **[Technique ID] Technique Name**: [Concrete explanation of the technique and how it functions]
- **Platforms Affected**: [e.g. Windows, Linux]

### 3. Adversary Procedures & Real-World Tooling
- **Known Tools/Malware**: [e.g. Mimikatz (S0002), ProcDump]
- **Execution Mechanism**: [e.g. LSASS handle rights 0x1010, rundll32 minidump, PowerShell]

### 4. Telemetry & Detection Data Sources
- **Data Component**: [e.g. Process: Process Access, Command: Command Execution]
- **Telemetry Event**: [e.g. Sysmon Event ID 10 (ProcessAccess to lsass.exe), Event ID 1]

### 5. Prioritized MITRE Defensive Mitigations
- **[Mitigation ID] Name**: [Specific technical mitigation such as Credential Guard, LSA Protection RunAsPPL]
"""

def test_query(q):
    print("=" * 60)
    print("QUERY:", q)
    res = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "openai/gpt-oss-120b"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": q},
        ],
        temperature=0.2,
        max_tokens=900,
    )
    print(res.choices[0].message.content)

if __name__ == "__main__":
    test_query("How do attackers steal passwords from memory?")
