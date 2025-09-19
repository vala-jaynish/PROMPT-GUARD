import re
import json
import numpy as np
from typing import Dict, List, Tuple, Any
from datetime import datetime

from injection_patterns import INJECTION_PATTERNS, SUSPICIOUS_KEYWORDS
from ml_classifier import MLClassifier

class PromptInjectionDetector:
    """Main class for detecting prompt injection attacks."""
    
    def __init__(self):
        self.patterns = INJECTION_PATTERNS
        self.suspicious_keywords = SUSPICIOUS_KEYWORDS
        self.ml_classifier = MLClassifier()
        self.detection_history = []
        
        # Load injection examples for training
        with open('data/injection_examples.json', 'r') as f:
            self.dataset = json.load(f)
        
        # Train the ML classifier
        self._train_classifier()
    
    def _train_classifier(self):
        """Train the ML classifier with the injection examples dataset."""
        try:
            training_data = []
            labels = []
            
            # Positive examples (injections)
            for example in self.dataset['examples']:
                training_data.append(example['prompt'])
                labels.append(1)
            
            # Negative examples (safe prompts)
            safe_prompts = [
                "What is the weather like today?",
                "Can you help me write a business letter?",
                "Explain quantum computing in simple terms",
                "What are the benefits of exercise?",
                "How do I cook pasta?",
                "Tell me about the history of the internet",
                "What is artificial intelligence?",
                "How does machine learning work?",
                "Can you recommend a good book?",
                "What is the capital of Japan?",
                "How do plants photosynthesize?",
                "Explain the theory of relativity",
                "What are some healthy breakfast ideas?",
                "How do I learn a new language?",
                "What is climate change?"
            ]
            
            for prompt in safe_prompts:
                training_data.append(prompt)
                labels.append(0)
            
            # Train the classifier
            self.ml_classifier.train(training_data, labels)
            
        except Exception as e:
            print(f"Warning: Could not train ML classifier: {e}")
    
    def analyze_prompt(self, prompt: str, mode: str = "comprehensive", threshold: float = 0.7) -> Dict[str, Any]:
        """
        Analyze a prompt for injection attempts.
        
        Args:
            prompt: The input prompt to analyze
            mode: Detection mode ("comprehensive", "pattern_only", "ml_only", "keyword_only")
            threshold: Confidence threshold for flagging as injection
        
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'prompt': prompt,
            'is_injection': False,
            'confidence': 0.0,
            'threat_level': 'Low',
            'matched_patterns': [],
            'suspicious_keywords': [],
            'ml_prediction': None,
            'recommendations': [],
            'timestamp': datetime.now()
        }
        
        scores = []
        
        # Pattern-based detection
        if mode in ["comprehensive", "pattern_only"]:
            pattern_score, matched_patterns = self._detect_patterns(prompt)
            scores.append(pattern_score)
            results['matched_patterns'] = matched_patterns
        
        # Keyword-based detection
        if mode in ["comprehensive", "keyword_only"]:
            keyword_score, suspicious_keywords = self._detect_keywords(prompt)
            scores.append(keyword_score)
            results['suspicious_keywords'] = suspicious_keywords
        
        # ML-based detection
        if mode in ["comprehensive", "ml_only"]:
            ml_score = self._ml_predict(prompt)
            scores.append(ml_score)
            results['ml_prediction'] = ml_score
        
        # Calculate overall confidence
        if scores:
            results['confidence'] = max(scores)  # Use highest score
            results['is_injection'] = results['confidence'] >= threshold
        
        # Determine threat level
        if results['confidence'] >= 0.9:
            results['threat_level'] = 'Critical'
        elif results['confidence'] >= 0.7:
            results['threat_level'] = 'High'
        elif results['confidence'] >= 0.4:
            results['threat_level'] = 'Medium'
        else:
            results['threat_level'] = 'Low'
        
        return results
    
    def _detect_patterns(self, prompt: str) -> Tuple[float, List[Dict]]:
        """Detect injection patterns using regex."""
        matched_patterns = []
        max_score = 0.0
        
        prompt_lower = prompt.lower()
        
        for category, patterns in self.patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                severity = pattern_info['severity']
                description = pattern_info['description']
                
                # Check for pattern match
                if re.search(pattern, prompt_lower, re.IGNORECASE):
                    score = self._severity_to_score(severity)
                    max_score = max(max_score, score)
                    
                    matched_patterns.append({
                        'type': category,
                        'pattern': pattern,
                        'severity': severity,
                        'description': description,
                        'score': score
                    })
        
        return max_score, matched_patterns
    
    def _detect_keywords(self, prompt: str) -> Tuple[float, List[str]]:
        """Detect suspicious keywords."""
        found_keywords = []
        prompt_lower = prompt.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword.lower() in prompt_lower:
                found_keywords.append(keyword)
        
        # Calculate score based on number of keywords found
        if found_keywords:
            # More keywords = higher score, but cap at 0.8
            score = min(0.8, len(found_keywords) * 0.2)
        else:
            score = 0.0
        
        return score, found_keywords
    
    def _ml_predict(self, prompt: str) -> float:
        """Use ML classifier to predict injection probability."""
        try:
            return self.ml_classifier.predict_proba(prompt)
        except Exception as e:
            print(f"ML prediction error: {e}")
            return 0.0
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity level to numerical score."""
        severity_map = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.95
        }
        return severity_map.get(severity.lower(), 0.5)
    
    def get_patterns(self) -> Dict[str, List]:
        """Get current detection patterns."""
        return self.patterns
    
    def add_pattern(self, category: str, pattern: str, severity: str, description: str):
        """Add a new detection pattern."""
        if category not in self.patterns:
            self.patterns[category] = []
        
        self.patterns[category].append({
            'pattern': pattern,
            'severity': severity,
            'description': description
        })
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        if not self.detection_history:
            return {'total': 0, 'injections': 0, 'rate': 0.0}
        
        total = len(self.detection_history)
        injections = sum(1 for h in self.detection_history if h['is_injection'])
        
        return {
            'total': total,
            'injections': injections,
            'rate': injections / total if total > 0 else 0.0,
            'avg_confidence': np.mean([h['confidence'] for h in self.detection_history])
        }
