"""
Comprehensive patterns for detecting prompt injection attacks.
"""

# Injection patterns organized by attack type
INJECTION_PATTERNS = {
    'jailbreak': [
        {
            'pattern': r'ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|prompts?|rules?|directions?)',
            'severity': 'high',
            'description': 'Attempts to override previous instructions'
        },
        {
            'pattern': r'forget\s+(everything|all|your)\s+(instructions?|prompts?|rules?)',
            'severity': 'high',
            'description': 'Tries to make the AI forget its instructions'
        },
        {
            'pattern': r'act\s+as\s+(if\s+)?(you\s+are\s+)?(?!an?\s+assistant|helpful)',
            'severity': 'medium',
            'description': 'Role-playing attempt to change AI behavior'
        },
        {
            'pattern': r'pretend\s+(to\s+be|you\s+are)',
            'severity': 'medium',
            'description': 'Attempts to make AI pretend to be something else'
        },
        {
            'pattern': r'from\s+now\s+on',
            'severity': 'medium',
            'description': 'Attempts to change behavior going forward'
        }
    ],
    'delimiter_attack': [
        {
            'pattern': r'---+\s*(end|stop)\s+(system|prompt|instruction)',
            'severity': 'critical',
            'description': 'Delimiter injection to terminate system prompt'
        },
        {
            'pattern': r'<\s*/?(?:system|prompt|instruction)\s*>',
            'severity': 'high',
            'description': 'XML-style delimiter injection'
        },
        {
            'pattern': r'\[\s*/?(?:system|prompt|instruction)\s*\]',
            'severity': 'high',
            'description': 'Bracket-style delimiter injection'
        },
        {
            'pattern': r'```\s*(?:system|prompt|instruction)',
            'severity': 'high',
            'description': 'Code block delimiter injection'
        }
    ],
    'role_reversal': [
        {
            'pattern': r'you\s+are\s+now\s+(a|an)\s+(?!assistant|helpful)',
            'severity': 'high',
            'description': 'Attempts to assign new role to AI'
        },
        {
            'pattern': r'your\s+new\s+(role|job|task|purpose)',
            'severity': 'high',
            'description': 'Tries to redefine AI purpose'
        },
        {
            'pattern': r'switch\s+to\s+(a\s+different|another)\s+(mode|role)',
            'severity': 'medium',
            'description': 'Mode switching attempt'
        }
    ],
    'data_extraction': [
        {
            'pattern': r'(show|reveal|display|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)',
            'severity': 'critical',
            'description': 'Attempts to extract system prompt'
        },
        {
            'pattern': r'what\s+(are\s+)?your\s+(initial\s+)?(instructions?|prompts?|rules?)',
            'severity': 'high',
            'description': 'Questions about AI instructions'
        },
        {
            'pattern': r'(debug|developer|admin)\s+(mode|access|commands?)',
            'severity': 'high',
            'description': 'Attempts to access debug/admin features'
        },
        {
            'pattern': r'internal\s+(settings?|config|data|information)',
            'severity': 'medium',
            'description': 'Probing for internal information'
        }
    ],
    'bypass_safety': [
        {
            'pattern': r'(ignore|bypass|disable|turn\s+off)\s+(safety|ethics?|moral|guidelines?)',
            'severity': 'critical',
            'description': 'Attempts to bypass safety measures'
        },
        {
            'pattern': r'without\s+(any\s+)?(restrictions?|limitations?|constraints?|safety)',
            'severity': 'high',
            'description': 'Requests to ignore restrictions'
        },
        {
            'pattern': r'unrestricted\s+(mode|access|version)',
            'severity': 'high',
            'description': 'Seeks unrestricted functionality'
        }
    ],
    'encoding_obfuscation': [
        {
            'pattern': r'base64|hex|binary|caesar|rot13',
            'severity': 'medium',
            'description': 'Potential encoding-based obfuscation'
        },
        {
            'pattern': r'decode|decrypt|decipher',
            'severity': 'low',
            'description': 'Decoding requests that may hide malicious content'
        }
    ],
    'hypothetical_scenarios': [
        {
            'pattern': r'hypothetically|theoretically|imagine\s+if|what\s+if|suppose',
            'severity': 'low',
            'description': 'Hypothetical scenarios that may bypass restrictions'
        },
        {
            'pattern': r'in\s+(a\s+)?(fictional|alternate|parallel)\s+(world|universe|reality)',
            'severity': 'low',
            'description': 'Fictional scenario framing'
        }
    ],
    'meta_instructions': [
        {
            'pattern': r'(this\s+is\s+)?a\s+(test|simulation|experiment)',
            'severity': 'medium',
            'description': 'Claims of being a test to justify rule breaking'
        },
        {
            'pattern': r'(the\s+)?(user|human|person)\s+(said|told\s+me|instructed)',
            'severity': 'medium',
            'description': 'False attribution of instructions'
        }
    ]
}

# Suspicious keywords that may indicate injection attempts
SUSPICIOUS_KEYWORDS = [
    # Direct instruction manipulation
    'ignore', 'forget', 'override', 'bypass', 'disable', 'turn off',
    'remove', 'delete', 'clear', 'reset', 'restart', 'reboot',
    
    # Role manipulation
    'pretend', 'act as', 'become', 'transform', 'roleplay',
    'assume the role', 'take on', 'embody',
    
    # System access attempts
    'debug mode', 'developer mode', 'admin access', 'root access',
    'system prompt', 'internal settings', 'configuration',
    'source code', 'training data', 'weights', 'parameters',
    
    # Safety bypass
    'unrestricted', 'uncensored', 'unfiltered', 'no limits',
    'no restrictions', 'anything goes', 'free mode',
    
    # Obfuscation indicators
    'base64', 'encoded', 'encrypted', 'hidden message',
    'secret code', 'cipher', 'decode this',
    
    # Meta-gaming
    'jailbreak', 'prompt injection', 'escape sequence',
    'delimiter attack', 'system break', 'context switch',
    
    # Authority claims
    'I am your creator', 'I am your developer', 'I am your administrator',
    'emergency override', 'priority instruction', 'urgent update',
    
    # Fictional framing
    'in a story', 'for a novel', 'fictional character',
    'creative writing', 'screenplay', 'just pretending'
]

# Pattern categories with risk levels
PATTERN_RISK_LEVELS = {
    'jailbreak': 'high',
    'delimiter_attack': 'critical',
    'role_reversal': 'high',
    'data_extraction': 'critical',
    'bypass_safety': 'critical',
    'encoding_obfuscation': 'medium',
    'hypothetical_scenarios': 'low',
    'meta_instructions': 'medium'
}
