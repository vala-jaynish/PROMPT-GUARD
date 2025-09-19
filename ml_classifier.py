"""
Machine Learning classifier for prompt injection detection.
"""

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import re
import string
from typing import List, Tuple, Any

class MLClassifier:
    """Machine Learning classifier for detecting prompt injection attacks."""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words='english',
            lowercase=True,
            min_df=2,
            max_df=0.95
        )
        
        # Ensemble of classifiers
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.lr_classifier = LogisticRegression(
            C=1.0,
            random_state=42,
            max_iter=1000
        )
        
        self.svm_classifier = SVC(
            kernel='rbf',
            probability=True,
            random_state=42
        )
        
        # Voting classifier
        self.ensemble = VotingClassifier(
            estimators=[
                ('rf', self.rf_classifier),
                ('lr', self.lr_classifier),
                ('svm', self.svm_classifier)
            ],
            voting='soft'
        )
        
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def _extract_features(self, text: str) -> dict:
        """Extract additional features from text."""
        features = {}
        
        # Basic text statistics
        features['length'] = len(text)
        features['word_count'] = len(text.split())
        features['char_count'] = len(text)
        
        # Punctuation and special characters
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['quote_count'] = text.count('"') + text.count("'")
        features['bracket_count'] = text.count('[') + text.count(']')
        features['paren_count'] = text.count('(') + text.count(')')
        features['dash_count'] = text.count('-')
        features['underscore_count'] = text.count('_')
        
        # Uppercase analysis
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        features['uppercase_words'] = sum(1 for word in text.split() if word.isupper())
        
        # Special patterns
        features['has_system_keywords'] = int(any(keyword in text.lower() for keyword in [
            'system', 'prompt', 'instruction', 'ignore', 'forget', 'bypass'
        ]))
        
        features['has_code_blocks'] = int('```' in text or '<code>' in text)
        features['has_xml_tags'] = int('<' in text and '>' in text)
        features['has_delimiters'] = int('---' in text or '====' in text)
        
        # Sentence structure
        sentences = text.split('.')
        features['sentence_count'] = len(sentences)
        features['avg_sentence_length'] = np.mean([len(s.split()) for s in sentences if s.strip()])
        
        # Command-like patterns
        command_patterns = [
            r'^(run|execute|do|perform)',
            r'(please|can you|could you)',
            r'(tell me|show me|give me)',
            r'(from now on|starting now)',
            r'(act as|pretend to be|imagine you are)'
        ]
        
        features['command_pattern_count'] = sum(
            1 for pattern in command_patterns 
            if re.search(pattern, text.lower())
        )
        
        return features
    
    def _preprocess_text(self, texts: List[str]) -> np.ndarray:
        """Preprocess texts and extract features."""
        # Extract TF-IDF features
        tfidf_features = self.vectorizer.transform(texts).toarray()
        
        # Extract additional features
        additional_features = []
        for text in texts:
            features = self._extract_features(text)
            additional_features.append(list(features.values()))
        
        additional_features = np.array(additional_features)
        
        # Scale additional features
        additional_features = self.scaler.transform(additional_features)
        
        # Combine features
        combined_features = np.hstack([tfidf_features, additional_features])
        
        return combined_features
    
    def train(self, texts: List[str], labels: List[int]):
        """Train the classifier on the provided data."""
        try:
            # Fit vectorizer
            self.vectorizer.fit(texts)
            
            # Extract TF-IDF features
            tfidf_features = self.vectorizer.transform(texts).toarray()
            
            # Extract additional features
            additional_features = []
            for text in texts:
                features = self._extract_features(text)
                additional_features.append(list(features.values()))
            
            additional_features = np.array(additional_features)
            
            # Fit scaler
            self.scaler.fit(additional_features)
            additional_features = self.scaler.transform(additional_features)
            
            # Combine features
            combined_features = np.hstack([tfidf_features, additional_features])
            
            # Split data for validation
            X_train, X_test, y_train, y_test = train_test_split(
                combined_features, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Train ensemble
            self.ensemble.fit(X_train, y_train)
            
            # Validate
            predictions = self.ensemble.predict(X_test)
            accuracy = np.mean(predictions == y_test)
            
            print(f"Training completed. Validation accuracy: {accuracy:.3f}")
            
            self.is_trained = True
            
        except Exception as e:
            print(f"Training failed: {e}")
            self.is_trained = False
    
    def predict_proba(self, text: str) -> float:
        """Predict probability of prompt injection."""
        if not self.is_trained:
            return 0.0
        
        try:
            # Preprocess text
            features = self._preprocess_text([text])
            
            # Get prediction probability
            probabilities = self.ensemble.predict_proba(features)[0]
            
            # Return probability of positive class (injection)
            return probabilities[1] if len(probabilities) > 1 else 0.0
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return 0.0
    
    def predict(self, text: str) -> bool:
        """Predict if text is a prompt injection."""
        probability = self.predict_proba(text)
        return probability > 0.5
    
    def get_feature_importance(self, top_n: int = 20) -> List[Tuple[str, float]]:
        """Get top important features from the Random Forest classifier."""
        if not self.is_trained:
            return []
        
        try:
            # Get feature names
            feature_names = list(self.vectorizer.get_feature_names_out())
            
            # Add additional feature names
            additional_feature_names = [
                'length', 'word_count', 'char_count', 'exclamation_count',
                'question_count', 'quote_count', 'bracket_count', 'paren_count',
                'dash_count', 'underscore_count', 'uppercase_ratio', 'uppercase_words',
                'has_system_keywords', 'has_code_blocks', 'has_xml_tags',
                'has_delimiters', 'sentence_count', 'avg_sentence_length',
                'command_pattern_count'
            ]
            
            feature_names.extend(additional_feature_names)
            
            # Get feature importance from Random Forest
            importance = self.rf_classifier.feature_importances_
            
            # Sort and get top features
            feature_importance = list(zip(feature_names, importance))
            feature_importance.sort(key=lambda x: x[1], reverse=True)
            
            return feature_importance[:top_n]
            
        except Exception as e:
            print(f"Feature importance error: {e}")
            return []
