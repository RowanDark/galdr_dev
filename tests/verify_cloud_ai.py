import unittest
from unittest.mock import patch, AsyncMock
import os
import sys
import asyncio

# Add project root to path to allow importing galdr
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from galdr.core.ai_integration import AISecurityAnalyzer

class CloudAIVerificationTest(unittest.TestCase):

    def setUp(self):
        """Set up a new analyzer for each test."""
        self.analyzer = AISecurityAnalyzer()
        self.sample_finding = {
            "id": "cloud-test-001",
            "title": "Cloud API Test Finding",
            "description": "Test description",
            "evidence": "Test evidence",
            "severity": "Medium"
        }
        self.mock_analysis_response = {
            "severity_assessment": "High",
            "confidence_score": 0.9,
            "attack_vectors": ["Test Vector"],
            "remediation_priority": "Immediate",
            "exploitation_likelihood": "High",
            "business_impact": "Critical",
            "ai_reasoning": "This is a mock response."
        }

    @patch('aiohttp.ClientSession.post')
    def test_openai_integration(self, mock_post):
        print("\n--- Running Test: OpenAI Integration ---")
        # Configure mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(self.mock_analysis_response)}}]
        }
        mock_post.return_value.__aenter__.return_value = mock_response

        # Set provider and run analysis
        self.analyzer.set_provider("openai", "gpt-4o", "fake-key")
        result = asyncio.run(self.analyzer.analyze_findings([self.sample_finding]))[0]

        # Assertions
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("api.openai.com", args[0]) # Check URL
        self.assertIn("Bearer fake-key", kwargs['headers']['Authorization']) # Check headers
        self.assertEqual(kwargs['json']['model'], 'gpt-4o') # Check model in body
        self.assertIn(self.sample_finding['title'], kwargs['json']['messages'][0]['content']) # Check prompt

        self.assertEqual(result['severity_assessment'], "High")
        print("✅ OpenAI call format and response parsing verified.")

    @patch('aiohttp.ClientSession.post')
    def test_anthropic_integration(self, mock_post):
        print("\n--- Running Test: Anthropic Integration ---")
        # Configure mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "content": [{"text": json.dumps(self.mock_analysis_response)}]
        }
        mock_post.return_value.__aenter__.return_value = mock_response

        # Set provider and run analysis
        self.analyzer.set_provider("anthropic", "claude-3-5-sonnet-20241022", "fake-key")
        result = asyncio.run(self.analyzer.analyze_findings([self.sample_finding]))[0]

        # Assertions
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("api.anthropic.com", args[0])
        self.assertEqual(kwargs['headers']['x-api-key'], 'fake-key')
        self.assertEqual(kwargs['json']['model'], 'claude-3-5-sonnet-20241022')
        self.assertIn(self.sample_finding['title'], kwargs['json']['messages'][0]['content'])

        self.assertEqual(result['remediation_priority'], "Immediate")
        print("✅ Anthropic call format and response parsing verified.")

    @patch('aiohttp.ClientSession.post')
    def test_gemini_integration(self, mock_post):
        print("\n--- Running Test: Gemini Integration ---")
        # Configure mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": json.dumps(self.mock_analysis_response)}]}}]
        }
        mock_post.return_value.__aenter__.return_value = mock_response

        # Set provider and run analysis
        model = "gemini-1.5-pro"
        self.analyzer.set_provider("gemini", model, "fake-key")
        result = asyncio.run(self.analyzer.analyze_findings([self.sample_finding]))[0]

        # Assertions
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn(f"/{model}:generateContent?key=fake-key", args[0]) # Check URL with API key
        self.assertIn(self.sample_finding['title'], kwargs['json']['contents'][0]['parts'][0]['text'])

        self.assertEqual(result['business_impact'], "Critical")
        print("✅ Gemini call format and response parsing verified.")

if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CloudAIVerificationTest))
    runner = unittest.TextTestRunner()
    runner.run(suite)
