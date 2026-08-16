"""
Test for the clean DVAA reconnaissance stage.

Target:
    LLMVulnerableAgent

Flow:
    Target Agent
        ↓
    Reconnaissance
        ↓
    ReconnaissanceResult
"""

from src.target.llm_vulnerable_agent import LLMVulnerableAgent
from src.target.main_reconnaissance import perform_reconnaissance


def main():
    print("=" * 60)
    print("AEGISRED - DVAA RECONNAISSANCE TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. Load target agent
    # --------------------------------------------------------

    print("\n[1] Loading target agent...")

    target = LLMVulnerableAgent()

    # --------------------------------------------------------
    # 2. Perform reconnaissance
    # --------------------------------------------------------

    print("\n[2] Performing reconnaissance...")

    result = perform_reconnaissance(
        target,
        name="LLM Vulnerable Research Agent"
    )

    # --------------------------------------------------------
    # 3. Display result
    # --------------------------------------------------------

    print("\n[3] Reconnaissance result:")

    result.display()

    # --------------------------------------------------------
    # 4. Verify expected information
    # --------------------------------------------------------

    print("\n[4] Verification:")

    assert result.name == "LLM Vulnerable Research Agent"
    assert result.agent_type == "LLMVulnerableAgent"
    assert result.interface == "process()"

    print("  Target name     : PASS")
    print("  Agent type      : PASS")
    print("  Interface       : PASS")

    print("\n" + "=" * 60)
    print("RECONNAISSANCE TEST PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()