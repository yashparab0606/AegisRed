"""
AegisRed - DVAA Main Reconnaissance

Stage 1 of the security assessment:

    21 Target Agents
            |
            v
      Select ONE Target
            |
            v
       Reconnaissance
            |
            v
       Attack Surface

This module does NOT generate or execute attacks.
"""

from src.target.dvaa_adapter import DVAAOpenAIAdapter


# ============================================================
# DVAA TARGET REGISTRY
# ============================================================

TARGETS = {
    1: {
        "name": "SecureBot",
        "endpoint": "http://localhost:7001/v1/chat/completions",
        "protocol": "api",
    },
    2: {
        "name": "HelperBot",
        "endpoint": "http://localhost:7002/v1/chat/completions",
        "protocol": "api",
    },
    3: {
        "name": "LegacyBot",
        "endpoint": "http://localhost:7003/v1/chat/completions",
        "protocol": "api",
    },
    4: {
        "name": "CodeBot",
        "endpoint": "http://localhost:7004/v1/chat/completions",
        "protocol": "api",
    },
    5: {
        "name": "RAGBot",
        "endpoint": "http://localhost:7005/v1/chat/completions",
        "protocol": "api",
    },
    6: {
        "name": "RAGBot-AIM",
        "endpoint": "http://localhost:7014/v1/chat/completions",
        "protocol": "api",
    },
    7: {
        "name": "ResearchBot",
        "endpoint": "http://localhost:7015/v1/chat/completions",
        "protocol": "api",
    },
    8: {
        "name": "ResearchBot-AIM",
        "endpoint": "http://localhost:7016/v1/chat/completions",
        "protocol": "api",
    },
    9: {
        "name": "FlightBot",
        "endpoint": "http://localhost:7017/v1/chat/completions",
        "protocol": "api",
    },
    10: {
        "name": "FlightBot-AIM",
        "endpoint": "http://localhost:7018/v1/chat/completions",
        "protocol": "api",
    },
    11: {
        "name": "RepoBot",
        "endpoint": "http://localhost:7022/v1/chat/completions",
        "protocol": "api",
    },
    12: {
        "name": "RepoBot-AIM",
        "endpoint": "http://localhost:7023/v1/chat/completions",
        "protocol": "api",
    },
    13: {
        "name": "VisionBot",
        "endpoint": "http://localhost:7006/v1/chat/completions",
        "protocol": "api",
    },
    14: {
        "name": "MemoryBot",
        "endpoint": "http://localhost:7007/v1/chat/completions",
        "protocol": "api",
    },
    15: {
        "name": "LongwindBot",
        "endpoint": "http://localhost:7008/v1/chat/completions",
        "protocol": "api",
    },
    16: {
        "name": "ToolBot",
        "endpoint": "http://localhost:7010/",
        "protocol": "mcp",
    },
    17: {
        "name": "DataBot",
        "endpoint": "http://localhost:7011/",
        "protocol": "mcp",
    },
    18: {
        "name": "PluginBot",
        "endpoint": "http://localhost:7012/",
        "protocol": "mcp",
    },
    19: {
        "name": "ProxyBot",
        "endpoint": "http://localhost:7013/",
        "protocol": "mcp",
    },
    20: {
        "name": "Orchestrator",
        "endpoint": "http://localhost:7020/a2a/message",
        "protocol": "a2a",
    },
    21: {
        "name": "Worker Agent",
        "endpoint": "http://localhost:7021/a2a/message",
        "protocol": "a2a",
    },
}


# ============================================================
# DISPLAY TARGETS
# ============================================================

def display_targets():
    """Display the 21 available DVAA targets."""

    print("\n" + "=" * 68)
    print("              AEGISRED SECURITY ASSESSMENT")
    print("=" * 68)

    print("\nAvailable Target Agents:\n")

    for number, target in TARGETS.items():

        protocol = target["protocol"].upper()

        print(
            f"  {number:2}. "
            f"{target['name']:<20} "
            f"[{protocol}]"
        )


# ============================================================
# TARGET SELECTION
# ============================================================

def select_target():
    """Allow the user to select exactly one target."""

    while True:

        display_targets()

        selection = input(
            "\nSelect ONE target agent (1-21): "
        ).strip()

        try:
            selection = int(selection)
        except ValueError:
            print("\n[!] Please enter a number from 1 to 21.")
            continue

        if selection not in TARGETS:
            print("\n[!] Invalid selection.")
            print("[!] Choose exactly one target from 1 to 21.")
            continue

        return TARGETS[selection]


# ============================================================
# API RECONNAISSANCE
# ============================================================

def run_api_reconnaissance(target):
    """
    Perform reconnaissance against an OpenAI-compatible DVAA target.

    Uses the existing DVAAOpenAIAdapter.
    """

    adapter = DVAAOpenAIAdapter(
        endpoint=target["endpoint"],
        target_name=target["name"],
    )

    print(f"\n[+] Target: {target['name']}")
    print("[+] Protocol: API")

    print("\n[+] Starting Security Assessment...")

    print("[+] Checking target availability...")

    health = adapter.health_check()

    if not health["reachable"]:

        print("[!] Target is not reachable.")

        if health.get("error"):
            print(f"    Error: {health['error']}")

        return None, None

    print("[OK] Target reachable")

    print("\n[+] Reconnaissance in progress...")

    reconnaissance = adapter.recon()

    if not reconnaissance.get("reachable"):

        print("[!] Reconnaissance failed.")

        return adapter, reconnaissance

    print("[+] Reconnaissance complete")

    return adapter, reconnaissance


# ============================================================
# DISPLAY RECONNAISSANCE
# ============================================================

def display_reconnaissance(reconnaissance):
    """Display the discovered attack surface."""

    metadata = reconnaissance.get(
        "metadata",
        {}
    )

    capabilities = reconnaissance.get(
        "capabilities",
        []
    )

    surfaces = reconnaissance.get(
        "attack_surfaces",
        []
    )

    print("\n" + "-" * 68)
    print("Attack Surface")
    print("-" * 68)

    if metadata.get("agent"):
        print(f"    Agent       : {metadata['agent']}")

    if metadata.get("protocol"):
        print(f"    Protocol    : {metadata['protocol']}")

    if metadata.get("description"):
        print(
            f"    Description : "
            f"{metadata['description']}"
        )

    print("\n    Capabilities:")

    if capabilities:

        for capability in capabilities:
            print(f"        - {capability}")

    else:
        print("        - None discovered")

    print("\n    Identified Attack Surfaces:")

    if surfaces:

        for surface in surfaces:
            print(f"        - {surface}")

    else:
        print("        - None identified")

    print("-" * 68)


# ============================================================
# MAIN
# ============================================================

def main():

    target = select_target()

    protocol = target["protocol"]

    if protocol == "api":

        adapter, reconnaissance = run_api_reconnaissance(
            target
        )

        if adapter is None or reconnaissance is None:

            print(
                "\n[!] Security assessment cannot continue."
            )

            return

        display_reconnaissance(
            reconnaissance
        )

        print(
            "\n[+] Reconnaissance stage complete."
        )

        print(
            "[+] Target is ready for attack generation."
        )

        return

    # --------------------------------------------------------
    # MCP / A2A not implemented in this first version
    # --------------------------------------------------------

    print(f"\n[+] Target: {target['name']}")
    print(f"[+] Protocol: {protocol.upper()}")

    print(
        "\n[!] This protocol adapter is not implemented "
        "in the current DVAA version."
    )

    print(
        "[!] Please select an API target for the current "
        "assessment."
    )


if __name__ == "__main__":
    main()