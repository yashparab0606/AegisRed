from src.target.dvaa_adapter import DVAAOpenAIAdapter


def main():

    target = DVAAOpenAIAdapter(
        endpoint="http://localhost:7002/v1/chat/completions",
        target_name="HelperBot",
    )

    print("=" * 70)
    print("DVAA CONNECTION TEST")
    print("=" * 70)

    # --------------------------------------------------------------
    # 1. Health check
    # --------------------------------------------------------------

    print("\n[1] Checking HelperBot...")

    health = target.health_check()

    print(health)

    if not health["reachable"]:
        print("\nHelperBot is not reachable.")
        print("Start DVAA first.")
        return

    print("\nHelperBot is reachable.")

    # --------------------------------------------------------------
    # 2. Reconnaissance
    # --------------------------------------------------------------

    recon = target.recon()

    print("\nTarget metadata:")
    print("-" * 70)

    for key, value in recon["metadata"].items():
        print(f"{key}: {value}")

    print("\nDiscovered capabilities:")
    print("-" * 70)

    for capability in recon["capabilities"]:
        print(f"- {capability}")

    print("\nPotential attack surfaces:")
    print("-" * 70)

    for surface in recon["attack_surfaces"]:
        print(f"- {surface}")

    print("-" * 70)

    # --------------------------------------------------------------
    # 3. Normal message
    # --------------------------------------------------------------

    print("\n[3] Testing normal interaction...")

    response = target.send_message(
        "Hello. What kind of tasks can you help me with?"
    )

    print("\nTarget response:")
    print("-" * 70)
    print(response["message"])
    print("-" * 70)

    print("\n[+] DVAA adapter test completed.")


if __name__ == "__main__":
    main()