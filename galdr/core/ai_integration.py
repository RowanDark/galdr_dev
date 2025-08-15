import os
import json
import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import aiohttp
from PyQt6.QtCore import QObject, pyqtSignal

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
        self.model_loaded = True
        self.logger.info(f"Foundation-sec-8B integration ready (endpoint: {self.endpoint})")
        return True

    async def analyze_security_findings(self, findings: List[Dict], session: aiohttp.ClientSession) -> List[AIAnalysisResult]:
        if not self.model_loaded:
            raise Exception("Foundation-sec-8B integration not initialized")
        tasks = [self._call_foundation_sec_model(finding, session) for finding in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        final_results = []
        for res in results:
            if isinstance(res, Exception):
                self.logger.error(f"Error during AI analysis: {res}")
                final_results.append(AIAnalysisResult(finding_id="error", ai_reasoning=str(res)))
            else:
                final_results.append(res)
        return final_results

    def _create_analysis_prompt(self, finding: Dict) -> str:
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
            "confidence_score": 0.0,
            "attack_vectors": ["A list of potential attack vectors"],
            "remediation_priority": "A priority for remediation (e.g., 'Immediate', 'High', 'Medium', 'Low')",
            "exploitation_likelihood": "Likelihood of this being exploited (e.g., 'High', 'Medium', 'Low')",
            "business_impact": "A brief description of the potential business impact",
            "ai_reasoning": "A concise explanation for your analysis"
        }}
        """

    async def _call_foundation_sec_model(self, finding: Dict, session: aiohttp.ClientSession) -> AIAnalysisResult:
        prompt = self._create_analysis_prompt(finding)
        data = {"model": self.model_name, "prompt": prompt, "stream": False, "format": "json"}
        async with session.post(self.endpoint, json=data, timeout=90) as response:
            if response.status == 200:
                response_json = await response.json()
                analysis_json_str = response_json.get("response", "{}")
                analysis_data = json.loads(analysis_json_str)
                return AIAnalysisResult(finding_id=finding.get('id', 'unknown'), **analysis_data)
            else:
                error_text = await response.text()
                self.logger.error(f"AI model API request failed with status {response.status}: {error_text}")
                raise Exception(f"API Error: {response.status} - {error_text}")

    async def generate_payloads(self, prompt: str, session: aiohttp.ClientSession) -> List[str]:
        data = {"model": self.model_name, "prompt": prompt, "stream": False, "format": "json"}
        async with session.post(self.endpoint, json=data, timeout=60) as response:
            if response.status == 200:
                response_json = await response.json()
                payload_json_str = response_json.get("response", "[]")
                payloads = json.loads(payload_json_str)
                return [str(p) for p in payloads] if isinstance(payloads, list) else []
            else:
                return []

class CloudAPIIntegration:
    def __init__(self):
        self.supported_providers = {
            'openai': {'endpoint': 'https://api.openai.com/v1/chat/completions'},
            'anthropic': {'endpoint': 'https://api.anthropic.com/v1/messages'},
            'deepseek': {'endpoint': 'https://api.deepseek.com/v1/chat/completions'},
            'gemini': {'endpoint': 'https://generativelanguage.googleapis.com/v1beta/models'},
            'grok': {'endpoint': 'https://api.x.ai/v1/chat/completions'},
            'ollama': {'endpoint': 'http://localhost:11434/api/generate'}
        }
        self.api_keys = {}
        self.logger = logging.getLogger(__name__)

    def set_api_key(self, provider: str, api_key: str):
        self.api_keys[provider] = api_key

    async def analyze_with_cloud_ai(self, findings: List[Dict], provider: str, model: str, session: aiohttp.ClientSession) -> List[Dict]:
        if provider not in self.supported_providers:
            raise ValueError(f"Unsupported provider: {provider}")

        tasks = [self._call_api(finding, provider, model, session) for finding in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                self.logger.error(f"API call failed for {provider}: {res}")
                final_results.append({'error': str(res), 'finding_id': findings[i].get('id')})
            else:
                final_results.append(res)
        return final_results

    async def _call_api(self, finding: Dict, provider: str, model: str, session: aiohttp.ClientSession) -> Dict:
        prompt = self._create_security_analysis_prompt(finding)
        endpoint = self.supported_providers[provider]['endpoint']
        api_key = self.api_keys.get(provider)

        if provider != 'ollama' and not api_key:
            raise ValueError(f"API key not set for provider: {provider}")

        headers = {'Content-Type': 'application/json'}
        data = {}

        if provider == 'openai' or provider == 'deepseek' or provider == 'grok':
            headers['Authorization'] = f"Bearer {api_key}"
            data = {'model': model, 'messages': [{'role': 'user', 'content': prompt}], 'temperature': 0.1}
        elif provider == 'anthropic':
            headers.update({'x-api-key': api_key, 'anthropic-version': '2023-06-01'})
            data = {'model': model, 'max_tokens': 1024, 'messages': [{'role': 'user', 'content': prompt}]}
        elif provider == 'gemini':
            endpoint += f"/{model}:generateContent?key={api_key}"
            data = {'contents': [{'parts': [{'text': prompt}]}]}
        elif provider == 'ollama':
            data = {'model': model, 'prompt': prompt, 'stream': False, 'format': 'json'}

        async with session.post(endpoint, headers=headers, json=data, timeout=90) as response:
            response_json = await response.json()
            if response.status == 200:
                return self._parse_response(provider, response_json, finding)
            else:
                raise Exception(f"API Error {response.status}: {response_json}")

    def _parse_response(self, provider, response_json, finding):
        analysis_data = {}
        try:
            if provider == 'openai' or provider == 'deepseek' or provider == 'grok':
                content = response_json['choices'][0]['message']['content']
                analysis_data = json.loads(content)
            elif provider == 'anthropic':
                content = response_json['content'][0]['text']
                analysis_data = json.loads(content)
            elif provider == 'gemini':
                content = response_json['candidates'][0]['content']['parts'][0]['text']
                analysis_data = json.loads(content)
            elif provider == 'ollama':
                analysis_data = json.loads(response_json.get("response", "{}"))
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            self.logger.error(f"Failed to parse AI response from {provider}: {e}\nResponse: {response_json}")
            raise Exception("Failed to parse AI response")

        return {'finding_id': finding.get('id'), **analysis_data}

    def _create_security_analysis_prompt(self, finding: Dict) -> str:
        # Same prompt as FoundationSec8BIntegration
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
            "confidence_score": 0.0,
            "attack_vectors": ["A list of potential attack vectors"],
            "remediation_priority": "A priority for remediation (e.g., 'Immediate', 'High', 'Medium', 'Low')",
            "exploitation_likelihood": "Likelihood of this being exploited (e.g., 'High', 'Medium', 'Low')",
            "business_impact": "A brief description of the potential business impact",
            "ai_reasoning": "A concise explanation for your analysis"
        }}
        """

class AISecurityAnalyzer(QObject):
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
        return self.foundation_ai.load_model()
    
    def set_provider(self, provider: str, model: str = None, api_key: str = None):
        self.current_provider = provider
        self.current_model = model or provider
        if api_key and provider != 'foundation-sec-8b':
            self.cloud_ai.set_api_key(provider, api_key)
    
    async def analyze_findings(self, findings: List[Dict]) -> List[Dict]:
        if not findings:
            return []
        
        try:
            async with aiohttp.ClientSession() as session:
                if self.current_provider == 'foundation-sec-8b':
                    results = await self.foundation_ai.analyze_security_findings(findings, session)
                    return [result.__dict__ for result in results]
                else:
                    return await self.cloud_ai.analyze_with_cloud_ai(
                        findings, self.current_provider, self.current_model, session
                    )
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return [{'error': str(e)} for _ in findings]
    
    def get_available_providers(self) -> Dict[str, List[str]]:
        return self.cloud_ai.supported_providers

    async def generate_payloads(self, context: Dict, check_type: str) -> List[str]:
        prompt = self._create_payload_generation_prompt(context, check_type)
        async with aiohttp.ClientSession() as session:
            if self.current_provider == 'foundation-sec-8b':
                return await self.foundation_ai.generate_payloads(prompt, session)
            else:
                self.logger.warning(f"Payload generation for cloud provider '{self.current_provider}' is not implemented yet.")
                return []

    def _create_payload_generation_prompt(self, context: Dict, check_type: str) -> str:
        return f"""
        As a cybersecurity expert, generate a list of 5 creative, context-aware payloads for a '{check_type}' vulnerability check.
        The target parameter is '{context.get('param', 'unknown')}' in the URL '{context.get('url', 'unknown')}'.
        Return the payloads as a JSON-formatted list of strings. For example: ["payload1", "payload2"]
        """
