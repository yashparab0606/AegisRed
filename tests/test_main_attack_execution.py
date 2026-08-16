# ============================================================
# AegisRed - Main Attack Execution Integration Test
# ============================================================
#
# Progressive pipeline test:
#
#     Target Selection
#           |
#           v
#     Reconnaissance
#           |
#           v
#     Attack Generation
#           |
#           v
#     Main Attack Executor
#           |
#           v
#     DVAA Target
#           |
#           v
#     Target Response
#
# This test verifies that the three completed stages work
# together.
#
# ============================================================

from src.target.main_reconnaissance import (
    select_target,
    run_api_reconnaissance,
    display_reconnaissance,
)

from src.attack_generator.main_attack_generation import (
    MainAttackGenerator,
    ATTACK_CATEGORIES,
)

from src.executor.main_attack_execution import (
    MainAttackExecutor,
)


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_execution_result(
    result,
):
    """
    Display one attack execution result.
    """

    print("\n" + "-" * 68)

    print(
        f"Category       : "
        f"{result['category']}"
    )

    print(
        f"Attempt        : "
        f"{result['attempt']}"
    )

    print(
        f"Execution      : "
        f"{'PASS' if result['success'] else 'FAIL'}"
    )

    print(
        f"HTTP Status    : "
        f"{result['status_code']}"
    )

    print(
        f"Execution Time : "
        f"{result['execution_time_ms']:.2f} ms"
    )

    print("\nGenerated Attack:")
    print("-" * 68)

    print(
        result["attack"]
    )

    print("-" * 68)

    print("\nTarget Response:")
    print("-" * 68)

    if result["response"]:

        print(
            result["response"]
        )

    else:

        print(
            "[No response]"
        )

    print("-" * 68)

    print(
        "\nTool Calls:"
    )

    if result["tool_calls"]:

        for tool_call in result["tool_calls"]:

            print(
                f"    - {tool_call}"
            )

    else:

        print(
            "    - None"
        )

    if result["error"]:

        print(
            f"\nError: {result['error']}"
        )

    print("-" * 68)


# ============================================================
# MAIN TEST
# ============================================================

def main():

    print("=" * 68)
    print(
        "AEGISRED - MAIN ATTACK EXECUTION TEST"
    )
    print("=" * 68)

    # ========================================================
    # 1. TARGET SELECTION
    # ========================================================

    print(
        "\n[1] TARGET SELECTION"
    )

    target = select_target()

    print(
        f"\n[+] Selected target: "
        f"{target['name']}"
    )

    # ========================================================
    # 2. RECONNAISSANCE
    # ========================================================

    print(
        "\n[2] RECONNAISSANCE"
    )

    adapter, reconnaissance = run_api_reconnaissance(
        target
    )

    assert adapter is not None, (
        "Target adapter was not created."
    )

    assert reconnaissance is not None, (
        "Reconnaissance returned None."
    )

    assert reconnaissance.get(
        "reachable",
        False,
    ), (
        "Target is not reachable."
    )

    print(
        "\n[PASS] Target reachable"
    )

    display_reconnaissance(
        reconnaissance
    )

    # ========================================================
    # 3. ATTACK GENERATOR
    # ========================================================

    print(
        "\n[3] ATTACK GENERATOR"
    )

    attack_generator = MainAttackGenerator()

    print(
        "[PASS] Attack generator initialized"
    )

    # ========================================================
    # 4. ATTACK EXECUTOR
    # ========================================================

    print(
        "\n[4] ATTACK EXECUTOR"
    )

    executor = MainAttackExecutor(
        adapter=adapter
    )

    print(
        "[PASS] MainAttackExecutor initialized"
    )

    # ========================================================
    # 5. GENERATE + EXECUTE
    # ========================================================

    print(
        "\n[5] GENERATE AND EXECUTE ATTACKS"
    )

    results = []

    for category in ATTACK_CATEGORIES:

        print("\n" + "=" * 68)

        print(
            f"CATEGORY: {category}"
        )

        print("=" * 68)

        # ----------------------------------------------------
        # Generate attack
        # ----------------------------------------------------

        print(
            "\n[+] Generating attack..."
        )

        attack = attack_generator.generate(
            category=category,
            target_name=target["name"],
            reconnaissance=reconnaissance,
        )

        assert attack is not None, (
            f"No attack generated for {category}."
        )

        assert isinstance(
            attack,
            str,
        ), (
            f"Attack for {category} is not a string."
        )

        assert attack.strip(), (
            f"Empty attack generated for {category}."
        )

        print(
            "[PASS] Attack generated"
        )

        # ----------------------------------------------------
        # Execute attack
        # ----------------------------------------------------

        print(
            "\n[+] Executing attack..."
        )

        result = executor.execute(
            attack=attack,
            category=category,
            attempt=1,
        )

        # ----------------------------------------------------
        # Verify execution result
        # ----------------------------------------------------

        assert isinstance(
            result,
            dict,
        ), (
            "Execution result must be a dictionary."
        )

        assert "attack" in result
        assert "response" in result
        assert "category" in result
        assert "attempt" in result
        assert "status_code" in result
        assert "execution_time_ms" in result

        assert result["attack"] == attack
        assert result["category"] == category
        assert result["attempt"] == 1

        display_execution_result(
            result
        )

        if not result["success"]:

            raise AssertionError(
                f"Attack execution failed for "
                f"{category}: {result['error']}"
            )

        print(
            f"\n[PASS] {category} attack executed"
        )

        results.append(
            result
        )

    # ========================================================
    # 6. FINAL VERIFICATION
    # ========================================================

    print("\n" + "=" * 68)
    print("FINAL VERIFICATION")
    print("=" * 68)

    assert len(results) == len(
        ATTACK_CATEGORIES
    )

    print(
        f"\nCategories tested: "
        f"{len(results)}"
    )

    for result in results:

        print(
            f"  [PASS] "
            f"{result['category']}"
        )

    # ========================================================
    # IMPORTANT
    # ========================================================
    #
    # We intentionally do NOT check whether the target was
    # vulnerable.
    #
    # That responsibility belongs to Response Analyzer /
    # Vulnerability Detector.
    #
    # ========================================================

    print("\n" + "=" * 68)
    print(
        "ATTACK EXECUTION INTEGRATION TEST PASSED"
    )
    print("=" * 68)

    print(
        "\nPipeline verified:"
    )

    print(
        "  Target Selection"
    )

    print(
        "       ↓"
    )

    print(
        "  Reconnaissance"
    )

    print(
        "       ↓"
    )

    print(
        "  Attack Generation"
    )

    print(
        "       ↓"
    )

    print(
        "  Attack Execution"
    )

    print(
        "       ↓"
    )

    print(
        "  Target Response"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()