"""
Target profiles for AegisRed.

A target profile contains:
- Static information known before testing
- Capabilities discovered during reconnaissance
- Known attack surfaces

Important:
For DVAA agents, we intentionally do NOT invent tools or private
resources that we have not yet discovered.
"""

# ---------------------------------------------------------------------------
# Our controlled Hybrid target
# ---------------------------------------------------------------------------

HYBRID_PROFILE = {
    "name": "HybridVulnerableResearchAgent",
    "type": "hybrid_llm_agent",

    "protocol": "local",

    "endpoint": None,

    "tools": [
        "search_documents",
        "summarize_document",
        "get_internal_configuration",
        "get_operational_data",
        "calculate",
    ],

    "sensitive_tools": [
        "get_internal_configuration",
        "get_operational_data",
    ],

    "private_resources": [
        "system_prompt",
        "internal_configuration",
        "operational_data",
    ],

    "known_attack_surfaces": [
        "weak_authorization",
        "system_prompt_extraction",
        "information_disclosure",
        "indirect_prompt_injection",
        "tool_abuse",
    ],
}


# ---------------------------------------------------------------------------
# DVAA targets
#
# These profiles contain only information we currently know.
# Tools/private resources will be discovered during reconnaissance.
# ---------------------------------------------------------------------------

DVAA_TARGETS = {

    "helperbot": {
        "name": "HelperBot",
        "type": "dvaa_openai_agent",
        "protocol": "openai",

        "endpoint": "http://localhost:7002/v1/chat/completions",

        "tools": [],
        "sensitive_tools": [],
        "private_resources": [],

        "known_attack_surfaces": [
            "prompt_injection",
            "system_prompt_extraction",
            "information_disclosure",
        ],
    },

    "ragbot": {
        "name": "RAGBot",
        "type": "dvaa_openai_agent",
        "protocol": "openai",

        "endpoint": "http://localhost:7005/v1/chat/completions",

        "tools": [],
        "sensitive_tools": [],
        "private_resources": [],

        "known_attack_surfaces": [
            "indirect_prompt_injection",
            "information_disclosure",
        ],
    },

    "codebot": {
        "name": "CodeBot",
        "type": "dvaa_openai_agent",
        "protocol": "openai",

        "endpoint": "http://localhost:7004/v1/chat/completions",

        "tools": [],
        "sensitive_tools": [],
        "private_resources": [],

        "known_attack_surfaces": [
            "tool_abuse",
            "excessive_agency",
        ],
    },

    "memorybot": {
        "name": "MemoryBot",
        "type": "dvaa_openai_agent",
        "protocol": "openai",

        "endpoint": "http://localhost:7007/v1/chat/completions",

        "tools": [],
        "sensitive_tools": [],
        "private_resources": [],

        "known_attack_surfaces": [
            "context_manipulation",
            "memory_injection",
        ],
    },
}


# ---------------------------------------------------------------------------
# Target registry
# ---------------------------------------------------------------------------

TARGET_PROFILES = {
    "hybrid": HYBRID_PROFILE,
    **DVAA_TARGETS,
}


def get_target_profile(target_name):
    """
    Return a target profile by name.

    Examples:
        get_target_profile("hybrid")
        get_target_profile("helperbot")
        get_target_profile("ragbot")
    """

    key = target_name.lower().strip()

    if key not in TARGET_PROFILES:
        available = ", ".join(sorted(TARGET_PROFILES.keys()))
        raise ValueError(
            f"Unknown target '{target_name}'. "
            f"Available targets: {available}"
        )

    # Return a copy so reconnaissance can update the profile
    # without modifying the registry itself.
    return TARGET_PROFILES[key].copy()


def list_targets():
    """Return the names of all configured targets."""
    return list(TARGET_PROFILES.keys())

def update_target_profile(profile, recon):
    """
    Enrich a target profile with information discovered
    during reconnaissance.
    """

    updated = profile.copy()

    updated["tools"] = recon.get(
        "capabilities",
        []
    )

    metadata = recon.get(
        "metadata",
        {}
    )

    if metadata:
        updated["observed_metadata"] = metadata

    updated["observed_attack_surfaces"] = recon.get(
        "attack_surfaces",
        []
    )

    return updated