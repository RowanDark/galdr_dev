import os
import json
import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import aiohttp

@dataclass
class AIAnalysisResult:
    finding_id: str
    severity_assessment: str = "N/A"
    confidence_score: float = 0.0
    attack_vectors: List[str] = field(default_factory=list)
    remediation_priority: str = "N/A"
    exploitation_likelihood: str = "N/A"
    business_impact: str = "N/A"
    ai_reasoning: str = "N/A"

class FoundationSec8BIntegration:
    """Native integration with Cisco's Foundation-sec-8B security model via Ollama."""
    
    def __init__(self, ollama_endpoint="http://localhost:11434/api/generate"):
        self.model_name = "foundation-sec-8b" # This should match the model name in Ollama
        self.endpoint = ollama_endpoint
        self.model_loaded = False
        self.logger = logging.getLogger(__name__)
        
    def load_model(self):
        """In this new architecture, we don't load the model directly. We just check if the endpoint is available."""
        # A simple health check could be added here, but for now we assume it's running.
        self.model_loaded = True
        self.logger.info(f"Foundation-sec-8B integration ready (endpoint: {self.endpoint})")
        return True

    async def analyze_security_findings(self, findings: List[Dict], session: aiohttp.ClientSession) -> List[AIAnalysisResult]:
        """Analyze security findings concurrently using the local AI model."""
        if not self.model_loaded:
            raise Exception("Foundation-sec-8B integration not initialized")

        tasks = [self._call_foundation_sec_model(finding, session) for finding in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results, handling potential errors from gather
        final_results = []
        for res in results:
            if isinstance(res, Exception):
                self.logger.error(f"Error during AI analysis: {res}")
                # Optionally create a result with an error message
                final_results.append(AIAnalysisResult(finding_id="error", ai_reasoning=str(res)))
            else:
                final_results.append(res)
        
        return final_results

    def _create_analysis_prompt(self, finding: Dict) -> str:
        """Creates a detailed prompt for the AI model to ensure a structured JSON response."""
        return f"""
        Analyze the following security finding and respond ONLY with a single, raw JSON object. Do not include markdown formatting or any text outside the JSON object.

        Finding Details:
        - Title: {finding.get('title', 'N/A')}
        - Severity: {finding.get('severity', 'N/A')}
        - URL: {finding.get('url', 'N/A')}
        - Evidence: {finding.get('evidence', 'N/A')}

        Based on the details, provide the following analysis in a JSON format with these exact keys:
        {{
            "severity_assessment": "Re-assess the severity (critical, high, medium, low, info)",
            "confidence_score": "A float from 0.0 to 1.0 indicating your confidence in the analysis",
            "attack_vectors": ["A list of potential attack vectors"],
            "remediation_priority": "A priority for remediation (e.g., 'Immediate', 'High', 'Medium', 'Low')",
            "exploitation_likelihood": "Likelihood of this being exploited (e.g., 'High', 'Medium', 'Low')",
            "business_impact": "A brief description of the potential business impact",
            "ai_reasoning": "A concise explanation for your analysis"
        }}
        """

    async def _call_foundation_sec_model(self, finding: Dict, session: aiohttp.ClientSession) -> AIAnalysisResult:
        """Calls the local Ollama-style API to get analysis for a single finding."""
        prompt = self._create_analysis_prompt(finding)
        data = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json" # Request JSON output from Ollama
        }
        
        try:
            async with session.post(self.endpoint, json=data, timeout=90) as response:
                if response.status == 200:
                    response_json = await response.json()
                    analysis_json_str = response_json.get("response", "{}")
                    analysis_data = json.loads(analysis_json_str)

                    return AIAnalysisResult(
                        finding_id=finding.get('id', 'unknown'),
                        severity_assessment=analysis_data.get("severity_assessment", "N/A"),
                        confidence_score=float(analysis_data.get("confidence_score", 0.0)),
                        attack_vectors=analysis_data.get("attack_vectors", []),
                        remediation_priority=analysis_data.get("remediation_priority", "N/A"),
                        exploitation_likelihood=analysis_data.get("exploitation_likelihood", "N/A"),
                        business_impact=analysis_data.get("business_impact", "N/A"),
                        ai_reasoning=analysis_data.get("ai_reasoning", "No reasoning provided.")
                    )
                else:
                    error_text = await response.text()
                    self.logger.error(f"AI model API request failed with status {response.status}: {error_text}")
                    raise Exception(f"API Error: {response.status} - {error_text}")
        except asyncio.TimeoutError:
            self.logger.error(f"Timeout calling AI model for finding: {finding.get('title')}")
            raise Exception("Request to AI model timed out.")
        except Exception as e:
            self.logger.error(f"Exception calling AI model: {e}")
            raise e

    async def generate_payloads(self, prompt: str, session: aiohttp.ClientSession) -> List[str]:
        """Calls the local Ollama-style API to generate payloads."""
        data = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        try:
            async with session.post(self.endpoint, json=data, timeout=60) as response:
                if response.status == 200:
                    response_json = await response.json()
                    # The prompt asks for a JSON list of strings.
                    payload_json_str = response_json.get("response", "[]")
                    payloads = json.loads(payload_json_str)
                    if isinstance(payloads, list):
                        return [str(p) for p in payloads]
                    else:
                        self.logger.warning(f"AI returned non-list for payloads: {payloads}")
                        return []
                else:
                    error_text = await response.text()
                    self.logger.error(f"AI payload API request failed with status {response.status}: {error_text}")
                    return []
        except Exception as e:
            self.logger.error(f"Exception calling AI for payload generation: {e}")
            return []


class CloudAPIIntegration:
    # ... (CloudAPIIntegration can be implemented later, keeping the class structure)
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    async def analyze_with_cloud_ai(self, findings: List[Dict], provider: str, model: str) -> List[Dict]:
        self.logger.warning("Cloud AI providers are not fully implemented yet.")
        return [{'error': 'Not Implemented', 'finding': f['id']} for f in findings]


class AISecurityAnalyzer(QObject):
    """Main AI security analyzer that coordinates different AI backends"""
    
    analysis_complete = pyqtSignal(list)
    analysis_progress = pyqtSignal(int, int)
    
    def __init__(self):
        super().__init__()
        self.foundation_ai = FoundationSec8BIntegration()
        self.cloud_ai = CloudAPIIntegration()
        self.current_provider = 'foundation-sec-8b'
        self.current_model = 'foundation-sec-8b'
        self.logger = logging.getLogger(__name__)
    
    def initialize(self):
        """Initialize AI systems"""
        return self.foundation_ai.load_model()
    
    def set_provider(self, provider: str, model: str = None, api_key: str = None):
        """Set AI provider and model"""
        self.current_provider = provider
        self.current_model = model or provider
        # API key handling for cloud would go here
    
    async def analyze_findings(self, findings: List[Dict]) -> List[Dict]:
        """Analyze security findings using configured AI provider."""
        if not findings:
            return []
        
        try:
            async with aiohttp.ClientSession() as session:
                if self.current_provider == 'foundation-sec-8b':
                    results = await self.foundation_ai.analyze_security_findings(findings, session)
                    return [result.__dict__ for result in results]
                else:
                    return await self.cloud_ai.analyze_with_cloud_ai(
                        findings, self.current_provider, self.current_model
                    )
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return [{'error': str(e)} for _ in findings]
    
    def get_available_providers(self) -> Dict[str, List[str]]:
        """Get list of available AI providers and models"""
        # This can be expanded later
        return {
            'foundation-sec-8b': ['foundation-sec-8b (Local)']
        }

    async def generate_payloads(self, context: Dict, check_type: str) -> List[str]:
        """Generates contextual payloads using the configured AI provider."""
        prompt = self._create_payload_generation_prompt(context, check_type)

        try:
            async with aiohttp.ClientSession() as session:
                # For now, we only implement this for the local/default provider
                if self.current_provider == 'foundation-sec-8b':
                    payloads = await self.foundation_ai.generate_payloads(prompt, session)
                    return payloads
                else:
                    self.logger.warning(f"Payload generation for provider '{self.current_provider}' is not implemented yet.")
                    return []
        except Exception as e:
            self.logger.error(f"AI payload generation failed: {e}")
            return []

    def _create_payload_generation_prompt(self, context: Dict, check_type: str) -> str:
        """Creates a prompt for generating context-aware security payloads."""
        return f"""
        As a cybersecurity expert, generate a list of 5 creative, context-aware payloads for a '{check_type}' vulnerability check.
        The target parameter is '{context.get('param', 'unknown')}' in the URL '{context.get('url', 'unknown')}'.
        Return the payloads as a JSON-formatted list of strings. For example: ["payload1", "payload2"]
        """
