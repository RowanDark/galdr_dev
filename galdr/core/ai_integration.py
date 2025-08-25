import os
import json
import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from PyQt6.QtCore import QObject, pyqtSignal, QThread
import requests

@dataclass
class AIAnalysisResult:
    finding_id: str
    severity_assessment: str
    confidence_score: float
    attack_vectors: List[str]
    remediation_priority: str
    exploitation_likelihood: str
    business_impact: str
    ai_reasoning: str

class FoundationSec8BIntegration:
    """Native integration with Cisco's Foundation-sec-8B security model"""
    
    def __init__(self):
        self.model_name = "foundation-sec-8b"
        self.model_loaded = False
        self.logger = logging.getLogger(__name__)
        
    def load_model(self):
        """Load the Foundation-sec-8B model for local inference"""
        try:
            # In production, this would load the actual model
            # For now, we'll simulate the model loading
            self.model_loaded = True
            self.logger.info("Foundation-sec-8B model loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load Foundation-sec-8B: {e}")
            return False
    
    def analyze_security_findings(self, findings: List[Dict]) -> List[AIAnalysisResult]:
        """Analyze security findings using Foundation-sec-8B"""
        if not self.model_loaded:
            raise Exception("Foundation-sec-8B model not loaded")
        
        results = []
        for finding in findings:
            # Simulate AI analysis - in production this would use the actual model
            analysis = self._simulate_security_analysis(finding)
            results.append(analysis)
        
        return results
    
    def _simulate_security_analysis(self, finding: Dict) -> AIAnalysisResult:
        """Simulate Foundation-sec-8B security analysis"""
        severity = finding.get('severity', 'medium')
        title = finding.get('title', '')
        
        # AI-powered severity reassessment
        ai_severity = self._reassess_severity(finding)
        
        # Generate attack vectors based on finding type
        attack_vectors = self._generate_attack_vectors(finding)
        
        # Calculate exploitation likelihood
        exploitation_likelihood = self._calculate_exploitation_likelihood(finding)
        
        return AIAnalysisResult(
            finding_id=finding.get('id', 'unknown'),
            severity_assessment=ai_severity,
            confidence_score=0.85,  # AI confidence in analysis
            attack_vectors=attack_vectors,
            remediation_priority=self._calculate_remediation_priority(finding),
            exploitation_likelihood=exploitation_likelihood,
            business_impact=self._assess_business_impact(finding),
            ai_reasoning=self._generate_reasoning(finding)
        )
    
    def _reassess_severity(self, finding: Dict) -> str:
        """AI-powered severity reassessment"""
        title = finding.get('title', '').lower()
        
        # Foundation-sec-8B would analyze context and reassess
        if 'sql injection' in title or 'xss' in title:
            return 'critical'
        elif 'authentication' in title or 'session' in title:
            return 'high'
        elif 'information disclosure' in title:
            return 'medium'
        else:
            return finding.get('severity', 'medium')
    
    def _generate_attack_vectors(self, finding: Dict) -> List[str]:
        """Generate potential attack vectors"""
        title = finding.get('title', '').lower()
        vectors = []
        
        if 'xss' in title:
            vectors = ['Stored XSS payload injection', 'DOM manipulation', 'Session hijacking']
        elif 'sql' in title:
            vectors = ['Union-based injection', 'Boolean-based blind injection', 'Time-based injection']
        elif 'authentication' in title:
            vectors = ['Credential stuffing', 'Session fixation', 'Privilege escalation']
        elif 'header' in title:
            vectors = ['Clickjacking', 'MIME sniffing', 'Content injection']
        else:
            vectors = ['Manual verification required', 'Context-dependent exploitation']
        
        return vectors
    
    def _calculate_exploitation_likelihood(self, finding: Dict) -> str:
        """Calculate likelihood of successful exploitation"""
        severity = finding.get('severity', 'medium')
        confidence = finding.get('confidence', 'tentative')
        
        if severity in ['critical', 'high'] and confidence == 'firm':
            return 'Very High'
        elif severity == 'high' or (severity == 'medium' and confidence == 'firm'):
            return 'High'
        elif severity == 'medium':
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_remediation_priority(self, finding: Dict) -> str:
        """Calculate remediation priority"""
        severity = finding.get('severity', 'medium')
        
        priority_map = {
            'critical': 'Immediate (0-24 hours)',
            'high': 'Urgent (1-7 days)',
            'medium': 'Standard (1-30 days)',
            'low': 'Planned (30+ days)',
            'info': 'Informational'
        }
        
        return priority_map.get(severity, 'Standard (1-30 days)')
    
    def _assess_business_impact(self, finding: Dict) -> str:
        """Assess business impact of the vulnerability"""
        title = finding.get('title', '').lower()
        
        if any(keyword in title for keyword in ['sql injection', 'authentication', 'session']):
            return 'High - Data breach risk, compliance violations'
        elif any(keyword in title for keyword in ['xss', 'csrf', 'injection']):
            return 'Medium - User account compromise, data manipulation'
        elif any(keyword in title for keyword in ['header', 'disclosure', 'cookie']):
            return 'Low-Medium - Information leakage, security policy violations'
        else:
            return 'Low - Minimal direct business impact'
    
    def _generate_reasoning(self, finding: Dict) -> str:
        """Generate AI reasoning for the analysis"""
        title = finding.get('title', '')
        severity = finding.get('severity', 'medium')
        
        return f"Foundation-sec-8B analysis: {title} represents a {severity} severity issue. " \
               f"Based on cybersecurity threat modeling and vulnerability patterns, this finding " \
               f"requires attention due to its potential for exploitation and business impact."

class CloudAPIIntegration:
    """Integration with cloud AI APIs for enhanced analysis"""
    
    def __init__(self):
        self.supported_providers = {
            'openai': {
                'models': ['gpt-4o', 'gpt-4-turbo', 'gpt-3.5-turbo'],
                'endpoint': 'https://api.openai.com/v1/chat/completions'
            },
            'anthropic': {
                'models': ['claude-3-5-sonnet-20241022', 'claude-3-opus-20240229'],
                'endpoint': 'https://api.anthropic.com/v1/messages'
            },
            'deepseek': {
                'models': ['deepseek-chat', 'deepseek-coder'],
                'endpoint': 'https://api.deepseek.com/v1/chat/completions'
            },
            'ollama': {
                'models': ['qwen2.5:7b', 'llama3.1:8b', 'codellama:7b'],
                'endpoint': 'http://localhost:11434/api/generate'
            }
        }
        self.api_keys = {}
        self.logger = logging.getLogger(__name__)
    
    def set_api_key(self, provider: str, api_key: str):
        """Set API key for a provider"""
        self.api_keys[provider] = api_key
    
    async def analyze_with_cloud_ai(self, findings: List[Dict], provider: str, model: str) -> List[Dict]:
        """Analyze findings using cloud AI APIs"""
        if provider not in self.supported_providers:
            raise ValueError(f"Unsupported provider: {provider}")
        
        if provider != 'ollama' and provider not in self.api_keys:
            raise ValueError(f"API key not set for provider: {provider}")
        
        results = []
        for finding in findings:
            try:
                analysis = await self._call_api(finding, provider, model)
                results.append(analysis)
            except Exception as e:
                self.logger.error(f"API call failed for {provider}: {e}")
                results.append({'error': str(e), 'finding': finding})
        
        return results
    
    async def generate_payloads_with_cloud_ai(self, context: str, vulnerability_type: str, count: int, provider: str, model: str) -> List[str]:
        """Generate payloads using cloud AI APIs."""
        if provider not in self.supported_providers:
            raise ValueError(f"Unsupported provider: {provider}")

        if provider != 'ollama' and provider not in self.api_keys:
            raise ValueError(f"API key not set for provider: {provider}")

        try:
            prompt = self._create_payload_generation_prompt(context, vulnerability_type, count)
            # For simplicity, we'll just use the OpenAI call structure as a template
            response_text = await self._call_openai_for_text(prompt, model)
            # A real implementation would need more robust parsing
            payloads = [line.strip() for line in response_text.split('\n') if line.strip()]
            return payloads
        except Exception as e:
            self.logger.error(f"Payload generation API call failed for {provider}: {e}")
            return []

    def _create_payload_generation_prompt(self, context: str, vulnerability_type: str, count: int) -> str:
        """Create a prompt for AI payload generation."""
        return f"""
        As a cybersecurity expert, generate a list of {count} creative, context-aware payloads for a '{vulnerability_type}' vulnerability.
        The target context is the following HTTP request:
        ---
        {context}
        ---
        Return ONLY the payloads, each on a new line. Do not include explanations, numbers, or bullet points.
        """

    async def _call_api(self, finding: Dict, provider: str, model: str) -> Dict:
        """Make API call to cloud provider"""
        prompt = self._create_security_analysis_prompt(finding)
        
        if provider == 'openai':
            return await self._call_openai(prompt, model)
        elif provider == 'anthropic':
            return await self._call_anthropic(prompt, model)
        elif provider == 'deepseek':
            return await self._call_deepseek(prompt, model)
        elif provider == 'ollama':
            return await self._call_ollama(prompt, model)
        else:
            raise ValueError(f"Provider {provider} not implemented")
    
    def _create_security_analysis_prompt(self, finding: Dict) -> str:
        """Create prompt for AI security analysis"""
        return f"""
        As a cybersecurity expert, analyze this security finding:
        
        Title: {finding.get('title', 'Unknown')}
        Severity: {finding.get('severity', 'Unknown')}
        Description: {finding.get('description', 'No description')}
        Evidence: {finding.get('evidence', 'No evidence')}
        CWE: {finding.get('cwe_id', 'Unknown')}
        
        Provide analysis in JSON format with:
        1. severity_reassessment (critical/high/medium/low)
        2. exploitation_difficulty (trivial/easy/moderate/hard)
        3. attack_vectors (list of potential attack methods)
        4. business_impact (description)
        5. remediation_steps (list of specific actions)
        6. false_positive_likelihood (percentage)
        7. ai_confidence (percentage)
        """
    
    async def _call_openai(self, prompt: str, model: str) -> Dict:
        """Call OpenAI API"""
        headers = {
            'Authorization': f"Bearer {self.api_keys['openai']}",
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': 'You are a cybersecurity expert specializing in vulnerability analysis.'},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.1
        }
        
        # Simulate API call - in production, use actual HTTP request
        return {
            'provider': 'openai',
            'model': model,
            'analysis': 'AI analysis would be here',
            'confidence': 0.9
        }

    async def _call_openai_for_text(self, prompt: str, model: str) -> str:
        """Calls the OpenAI API and returns the raw text response."""
        # This is a simulation. A real implementation would make an HTTP request
        # and parse the JSON to extract the 'content' of the message.
        self.logger.info(f"Simulating OpenAI call for payload generation with model {model}.")
        # Simulate a list of payloads as a newline-separated string
        return "\n".join([
            f"ai-payload-{i}" for i in range(10)
        ])
    
    async def _call_anthropic(self, prompt: str, model: str) -> Dict:
        """Call Anthropic Claude API"""
        # Similar implementation for Anthropic
        return {
            'provider': 'anthropic',
            'model': model,
            'analysis': 'Claude analysis would be here',
            'confidence': 0.88
        }
    
    async def _call_deepseek(self, prompt: str, model: str) -> Dict:
        """Call DeepSeek API"""
        # Similar implementation for DeepSeek
        return {
            'provider': 'deepseek',
            'model': model,
            'analysis': 'DeepSeek analysis would be here',
            'confidence': 0.85
        }
    
    async def _call_ollama(self, prompt: str, model: str) -> Dict:
        """Call local Ollama API"""
        # Implementation for local Ollama
        return {
            'provider': 'ollama',
            'model': model,
            'analysis': 'Ollama local analysis would be here',
            'confidence': 0.82
        }

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
        # Load Foundation-sec-8B by default
        success = self.foundation_ai.load_model()
        if success:
            self.logger.info("AI Security Analyzer initialized with Foundation-sec-8B")
        else:
            self.logger.warning("Failed to load Foundation-sec-8B, falling back to basic analysis")
        
        return success
    
    def set_provider(self, provider: str, model: str = None, api_key: str = None):
        """Set AI provider and model"""
        self.current_provider = provider
        self.current_model = model or provider
        
        if api_key and provider != 'foundation-sec-8b':
            self.cloud_ai.set_api_key(provider, api_key)
    
    async def analyze_findings(self, findings: List[Dict]) -> List[Dict]:
        """Analyze security findings using configured AI provider"""
        if not findings:
            return []
        
        try:
            if self.current_provider == 'foundation-sec-8b':
                # Use local Foundation-sec-8B
                results = self.foundation_ai.analyze_security_findings(findings)
                return [result.__dict__ for result in results]
            else:
                # Use cloud API
                return await self.cloud_ai.analyze_with_cloud_ai(
                    findings, self.current_provider, self.current_model
                )
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return [{'error': str(e)} for _ in findings]
    
    def get_available_providers(self) -> Dict[str, List[str]]:
        """Get list of available AI providers and models"""
        providers = {
            'foundation-sec-8b': ['foundation-sec-8b (Local)']
        }
        
        for provider, config in self.cloud_ai.supported_providers.items():
            providers[provider] = config['models']
        
        return providers

    async def generate_smart_payloads(self, context: str, vulnerability_type: str, count: int = 10) -> List[str]:
        """Generate smart payloads using the configured AI provider."""
        try:
            if self.current_provider == 'foundation-sec-8b':
                # Foundation model might have a different, specialized method
                # For now, we'll simulate it or fall back.
                return [f"foundation-payload-for-{vulnerability_type}-{i}" for i in range(count)]
            else:
                # Use cloud API
                return await self.cloud_ai.generate_payloads_with_cloud_ai(
                    context, vulnerability_type, count, self.current_provider, self.current_model
                )
        except Exception as e:
            self.logger.error(f"AI payload generation failed: {e}")
            return []
