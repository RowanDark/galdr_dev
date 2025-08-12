import asyncio
from galdr.core.ai_integration import AISecurityAnalyzer

async def verify_ai_analyzer():
    """
    Tests the AI analyzer by sending a sample finding.
    Requires a running Ollama instance with the 'foundation-sec-8b' model.
    """
    print("\n--- Running Test: AI Analyzer ---")
    analyzer = AISecurityAnalyzer()

    if not analyzer.initialize():
        print("❌ Test FAILED: AI Analyzer failed to initialize.")
        return False

    sample_finding = {
        "id": "test-001",
        "title": "Cross-Site Scripting (XSS)",
        "description": "A reflected XSS vulnerability was found in the search parameter.",
        "evidence": "The payload `<script>alert(1)</script>` was executed.",
        "severity": "High"
    }

    print("Analyzing sample finding with AI...")
    try:
        results = await analyzer.analyze_findings([sample_finding])
    except Exception as e:
        print(f"❌ Test FAILED: An exception occurred during analysis: {e}")
        print("    Please ensure a local Ollama-compatible API is running at http://localhost:11434")
        print("    and that it is serving a model named 'foundation-sec-8b'.")
        return False

    if not results:
        print("❌ Test FAILED: AI analysis returned no results.")
        return False

    result = results[0]
    if "error" in result:
        print(f"❌ Test FAILED: AI analysis returned an error: {result.get('error')}")
        return False

    print(f"✅ AI Analysis Result: {result}")

    # Check that the result has the expected structure
    if "ai_reasoning" not in result or not result["ai_reasoning"]:
        print("❌ Test FAILED: AI reasoning is missing or empty.")
        return False

    if "attack_vectors" not in result or not isinstance(result['attack_vectors'], list):
        print("❌ Test FAILED: Attack vectors are missing or not a list.")
        return False

    print("--- ✅ Test Passed: AI Analyzer ---")
    return True

if __name__ == "__main__":
    print("Starting AI feature verification script...")
    if asyncio.run(verify_ai_analyzer()):
        exit(0)
    else:
        exit(1)
