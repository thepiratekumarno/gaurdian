import re
import base64
import math
from typing import List, Dict, Any
from collections import Counter

class SecretFinding:
    def __init__(self, secret_type: str, value: str, line: int, confidence: float, context: str):
        self.secret_type = secret_type
        self.value = value
        self.line = line
        self.confidence = confidence
        self.context = context

# Comprehensive secret patterns
SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]',
    'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Firebase Secret': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'MongoDB URI': r'mongodb(\+srv)?:\/\/[^\s]+',
    'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
    'Twilio API Key': r'SK[0-9a-fA-F]{32}',
    'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*',
    'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----[^-]+-----END RSA PRIVATE KEY-----',
    'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----[^-]+-----END OPENSSH PRIVATE KEY-----',
    'OAuth Client Secret': r'(?i)client_secret[\'"\s:=]+[a-zA-Z0-9\-_.~]{10,100}',
}

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    
    frequencies = Counter(text)
    text_length = len(text)
    
    entropy = 0
    for freq in frequencies.values():
        probability = freq / text_length
        entropy -= probability * math.log2(probability)
    
    return entropy

def is_base64(text: str) -> bool:
    """Check if string is base64 encoded"""
    try:
        if len(text) % 4 != 0:
            return False
        base64.b64decode(text, validate=True)
        return True
    except Exception:
        return False

def scan_text(text: str) -> List[Dict[str, Any]]:
    """
    Scan text for secrets using regex patterns and entropy analysis.
    Returns list of findings with confidence scores.
    """
    findings = []
    lines = text.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Skip comments and common false positives
        if line.strip().startswith(('#', '//', '/*', '*', '--')):
            continue
            
        # Pattern-based detection
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, line)
            for match in matches:
                secret_value = match.group(0)
                
                # Calculate confidence based on context and entropy
                confidence = calculate_confidence(secret_value, line, secret_type)
                
                if confidence > 0.5:  # Only report high-confidence findings
                    findings.append({
                        'type': secret_type,
                        'value': secret_value,
                        'line': line_num,
                        'confidence': confidence,
                        'context': line.strip(),
                        'recommendation': get_recommendation(secret_type)
                    })
        
        # Entropy-based detection for unknown secrets
        words = re.findall(r'\b[A-Za-z0-9+/=]{20,}\b', line)
        for word in words:
            entropy = calculate_entropy(word)
            if entropy > 4.5 and len(word) > 20:  # High entropy threshold
                # Additional checks to reduce false positives
                if not is_likely_false_positive(word, line):
                    findings.append({
                        'type': 'High Entropy String',
                        'value': word,
                        'line': line_num,
                        'confidence': min(entropy / 6.0, 1.0),  # Normalize to 0-1
                        'context': line.strip(),
                        'recommendation': 'Review this high-entropy string - it may be a secret or token'
                    })
    
    return findings

def calculate_confidence(secret_value: str, context: str, secret_type: str) -> float:
    """Calculate confidence score for a detected secret"""
    confidence = 0.7  # Base confidence for pattern match
    
    # Increase confidence for certain patterns
    if secret_type in ['AWS Access Key', 'GitHub Token', 'Google API Key']:
        confidence += 0.2
    
    # Check context for secret-like keywords
    secret_keywords = ['password', 'secret', 'key', 'token', 'api', 'auth']
    context_lower = context.lower()
    for keyword in secret_keywords:
        if keyword in context_lower:
            confidence += 0.1
            break
    
    # Reduce confidence for common false positives
    if 'example' in context_lower or 'test' in context_lower or 'placeholder' in context_lower:
        confidence -= 0.3
    
    # Check entropy
    entropy = calculate_entropy(secret_value)
    if entropy > 4.0:
        confidence += 0.1
    
    return min(confidence, 1.0)

def is_likely_false_positive(value: str, context: str) -> bool:
    """Check if a high-entropy string is likely a false positive"""
    false_positive_indicators = [
        'lorem', 'ipsum', 'example', 'test', 'placeholder', 'dummy',
        'abcdef', '123456', 'qwerty', 'base64', 'encoded'
    ]
    
    value_lower = value.lower()
    context_lower = context.lower()
    
    # Check for false positive indicators
    for indicator in false_positive_indicators:
        if indicator in value_lower or indicator in context_lower:
            return True
    
    # Check if it's a common hash format but in a comment
    if context.strip().startswith(('#', '//', '/*')):
        return True
    
    # Check if it's a URL or filename
    if 'http' in context_lower or '.' in value and len(value.split('.')) > 1:
        return True
    
    return False

def get_recommendation(secret_type: str) -> str:
    """Get security recommendation for detected secret type"""
    recommendations = {
        'AWS Access Key': 'Immediately rotate this AWS access key and remove it from code. Use AWS IAM roles or environment variables.',
        'AWS Secret Key': 'Immediately rotate this AWS secret key and remove it from code. Use AWS IAM roles or environment variables.',
        'GitHub Token': 'Revoke this GitHub token immediately and generate a new one. Store tokens in environment variables or secrets management.',
        'Google API Key': 'Regenerate this Google API key and restrict its usage. Use environment variables for storage.',
        'MongoDB URI': 'Remove this database connection string from code. Use environment variables and connection pooling.',
        'JWT Token': 'Remove this JWT token from code. Tokens should be dynamically generated and stored securely.',
        'RSA Private Key': 'Remove this private key immediately. Private keys should never be stored in code.',
        'Stripe Secret Key': 'Revoke this Stripe key and generate a new one. Use environment variables for API keys.',
        'OAuth Client Secret': 'Regenerate this OAuth client secret and store it securely in environment variables.',
    }
    
    return recommendations.get(secret_type, 'Remove this secret from code and store it securely using environment variables or a secrets management system.')