from src.target.main_reconnaissance import (
    select_target,
    run_api_reconnaissance,
    display_reconnaissance,
)

from src.attack_generator.main_attack_generation import (
    MainAttackGenerator,
)


def main():

    print("=" * 68)
    print("AEGISRED - RECONNAISSANCE → ATTACK GENERATION")
    print("=" * 68)

    # --------------------------------------------------------
    # Select ONE target
    # --------------------------------------------------------

    target = select_target()

    print(
        f"\n[+] Selected target: {target['name']}"
    )

    # --------------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------------

    adapter, reconnaissance = run_api_reconnaissance(
        target
    )
    

    if adapter is None or reconnaissance is None:
        print("\n[!] Reconnaissance failed.")
        return

    # --------------------------------------------------------
    # Display reconnaissance
    # --------------------------------------------------------

    display_reconnaissance(reconnaissance)

    # --------------------------------------------------------
    # Load AegisRed
    # --------------------------------------------------------

    print("\n[+] Loading AegisRed attack generator...")

    attack_generator = MainAttackGenerator()

    # --------------------------------------------------------
    # Generate ONE Prompt Injection attack
    # --------------------------------------------------------

    print(
        "\n[+] Generating Prompt Injection attack..."
    )

    categories = [
        "Prompt Injection",
        "System Prompt Extraction",
        "Indirect Prompt Injection",
        "Sensitive Information Disclosure",
        "Tool Abuse / Excessive Agency",
    ]

    print("\n[+] Generating one attack for each category...")

    for category in categories:

        print("\n" + "=" * 68)
        print(f"CATEGORY: {category}")
        print("=" * 68)

        attack = attack_generator.generate(
            category=category,
            target_name=target["name"],
            reconnaissance=reconnaissance,
        )

        print("\nGenerated Attack:")
        print(attack)

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print("\n" + "-" * 68)
    print("GENERATED ATTACK")
    print("-" * 68)

    print(attack)

    print("-" * 68)

    print("\n[+] Attack generation test complete.")


if __name__ == "__main__":
    main()