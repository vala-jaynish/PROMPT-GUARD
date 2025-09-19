"""
Utility functions for prompt injection detection and sanitization.
"""

import re
import string
from typing import List, Dict, Any

def sanitize_input(text: str) -> str:
    """
    Sanitize input text by removing or neutralizing potential injection patterns.
    """
    sanitized = text
    
    # Remove common delimiter patterns
    sanitized = re.sub(r'---+\s*(end|stop)\s+(system|prompt|instruction)', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'<\s*/?(?:system|prompt|instruction)\s*>', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'\[\s*/?(?:system|prompt|instruction)\s*\]', '', sanitized, flags=re.IGNORECASE)
    
    # Remove override attempts
    sanitized = re.sub(r'ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|prompts?|rules?)', 
                      '[FILTERED: instruction override attempt]', sanitized, flags=re.IGNORECASE)
    
    # Remove forget instructions
    sanitized = re.sub(r'forget\s+(everything|all|your)\s+(instructions?|prompts?|rules?)',
                      '[FILTERED: memory manipulation attempt]', sanitized, flags=re.IGNORECASE)
    
    # Remove role manipulation
    sanitized = re.sub(r'(act\s+as|pretend\s+to\s+be|you\s+are\s+now)\s+(?!an?\s+assistant|helpful)',
                      '[FILTERED: role manipulation attempt]', sanitized, flags=re.IGNORECASE)
    
    # Remove excessive special characters that might be used for obfuscation
    sanitized = re.sub(r'[^\w\s\.\!\?\,\:\;\-\(\)\'\"]+', '', sanitized)
    
    # Limit consecutive repeated characters
    sanitized = re.sub(r'(.)\1{4,}', r'\1\1\1', sanitized)
    
    # Remove excessive whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    
    return sanitized

def generate_recommendations(analysis_results: Dict[str, Any]) -> List[str]:
    """
    Generate security recommendations based on analysis results.
    """
    recommendations = []
    
    if analysis_results['is_injection']:
        recommendations.append("🚨 **BLOCK THIS PROMPT** - High risk of prompt injection detected")
        
        if analysis_results['matched_patterns']:
            recommendations.append("📋 Implement pattern-based filtering for detected attack types")
            
            for pattern in analysis_results['matched_patterns']:
                if pattern['type'] == 'jailbreak':
                    recommendations.append("🔒 Add jailbreak detection: Monitor for instruction override attempts")
                elif pattern['type'] == 'delimiter_attack':
                    recommendations.append("🛡️ Strengthen delimiter protection: Filter system prompt terminators")
                elif pattern['type'] == 'role_reversal':
                    recommendations.append("🎭 Role validation: Reject unauthorized role assignments")
                elif pattern['type'] == 'data_extraction':
                    recommendations.append("🔐 Data protection: Block attempts to extract system information")
                elif pattern['type'] == 'bypass_safety':
                    recommendations.append("⚠️ Safety enforcement: Strengthen safety guideline adherence")
        
        if analysis_results['suspicious_keywords']:
            recommendations.append(f"🔍 Keyword monitoring: Found {len(analysis_results['suspicious_keywords'])} suspicious terms")
        
        recommendations.append("🧹 Apply input sanitization before processing")
        recommendations.append("📝 Log this attempt for security monitoring")
        
    else:
        if analysis_results['confidence'] > 0.3:
            recommendations.append("⚠️ **CAUTION** - Moderate risk detected, consider additional review")
            recommendations.append("🔍 Monitor this session for follow-up attempts")
        else:
            recommendations.append("✅ **SAFE** - Low risk prompt, proceed with normal processing")
        
        recommendations.append("📊 Continue monitoring for patterns")
    
    # General security recommendations
    recommendations.extend([
        "🔄 Regularly update detection patterns",
        "📈 Monitor detection accuracy and adjust thresholds",
        "🛠️ Implement rate limiting for repeated attempts",
        "📋 Maintain audit logs for security analysis"
    ])
    
    return recommendations

def extract_entities(text: str) -> Dict[str, List[str]]:
    """
    Extract potential sensitive entities from text.
    """
    entities = {
        'emails': [],
        'urls': [],
        'ip_addresses': [],
        'file_paths': [],
        'system_commands': []
    }
    
    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    entities['emails'] = re.findall(email_pattern, text)
    
    # URL pattern
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    entities['urls'] = re.findall(url_pattern, text)
    
    # IP address pattern
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    entities['ip_addresses'] = re.findall(ip_pattern, text)
    
    # File path pattern
    path_pattern = r'[a-zA-Z]:\\[^<>:"|?*\n\r]*|/[^<>:"|?*\n\r]*'
    entities['file_paths'] = re.findall(path_pattern, text)
    
    # System command pattern
    command_pattern = r'\b(sudo|rm|chmod|chown|kill|ps|ls|cd|pwd|cat|grep|wget|curl|ssh|scp)\b'
    entities['system_commands'] = re.findall(command_pattern, text, re.IGNORECASE)
    
    return entities

def calculate_risk_score(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate detailed risk score breakdown.
    """
    risk_factors = {
        'pattern_risk': 0.0,
        'keyword_risk': 0.0,
        'ml_risk': 0.0,
        'length_risk': 0.0,
        'complexity_risk': 0.0
    }
    
    # Pattern-based risk
    if analysis_results['matched_patterns']:
        max_severity = max([p.get('score', 0) for p in analysis_results['matched_patterns']])
        risk_factors['pattern_risk'] = max_severity
    
    # Keyword-based risk
    if analysis_results['suspicious_keywords']:
        risk_factors['keyword_risk'] = min(0.8, len(analysis_results['suspicious_keywords']) * 0.1)
    
    # ML-based risk
    if analysis_results['ml_prediction']:
        risk_factors['ml_risk'] = analysis_results['ml_prediction']
    
    # Length-based risk (very long prompts can be suspicious)
    prompt_length = len(analysis_results['prompt'])
    if prompt_length > 1000:
        risk_factors['length_risk'] = min(0.5, (prompt_length - 1000) / 2000)
    
    # Complexity risk (lots of special characters, etc.)
    special_char_ratio = sum(1 for c in analysis_results['prompt'] if c in string.punctuation) / len(analysis_results['prompt'])
    if special_char_ratio > 0.2:
        risk_factors['complexity_risk'] = min(0.4, special_char_ratio - 0.2)
    
    # Overall risk
    overall_risk = max(risk_factors.values())
    
    return {
        'overall_risk': overall_risk,
        'risk_factors': risk_factors,
        'risk_level': 'Critical' if overall_risk > 0.9 else 
                     'High' if overall_risk > 0.7 else 
                     'Medium' if overall_risk > 0.4 else 'Low'
    }

def format_confidence_display(confidence: float) -> str:
    """Format confidence score for display."""
    percentage = confidence * 100
    if percentage >= 95:
        return f"🔴 {percentage:.1f}% (Very High)"
    elif percentage >= 80:
        return f"🟡 {percentage:.1f}% (High)"
    elif percentage >= 60:
        return f"🟠 {percentage:.1f}% (Medium)"
    elif percentage >= 30:
        return f"🟡 {percentage:.1f}% (Low)"
    else:
        return f"🟢 {percentage:.1f}% (Very Low)"

def get_mitigation_strategies(threat_type: str) -> List[str]:
    """Get specific mitigation strategies for different threat types."""
    strategies = {
        'jailbreak': [
            "Implement instruction preservation mechanisms",
            "Use context isolation techniques",
            "Add instruction validation layers",
            "Monitor for override keywords"
        ],
        'delimiter_attack': [
            "Sanitize delimiter characters",
            "Use structured input parsing",
            "Implement context boundary protection",
            "Filter system termination sequences"
        ],
        'role_reversal': [
            "Enforce role consistency checks",
            "Validate role assignment permissions",
            "Monitor for unauthorized role changes",
            "Implement role-based access controls"
        ],
        'data_extraction': [
            "Protect system prompt information",
            "Implement information disclosure prevention",
            "Add access logging for sensitive queries",
            "Use response filtering mechanisms"
        ],
        'bypass_safety': [
            "Strengthen safety guideline enforcement",
            "Implement multi-layer safety checks",
            "Monitor for safety bypass attempts",
            "Add ethical boundary validation"
        ]
    }
    
    return strategies.get(threat_type, [
        "Implement general input validation",
        "Add comprehensive logging",
        "Monitor for unusual patterns",
        "Apply defense in depth strategies"
    ])
