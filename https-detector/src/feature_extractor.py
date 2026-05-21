import re
import math
import tldextract
from urllib.parse import urlparse

class URLFeatureExtractor:
    def __init__(self):
        # Common special characters found in URLs
        self.special_chars = ['-', '@', '?', '=', '.', '//', 'http', 'https', 'www', '_', '&', '%', '+', '*']
        
    def _entropy(self, string):
        """Calculate Shannon entropy of a string."""
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def _has_ip(self, url):
        """Check if URL uses an IP address instead of a domain name."""
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
        return 1 if match else 0

    def extract(self, url):
        """Extract lexical and structural features from a URL."""
        if not url.startswith('http'):
            # Prepend a scheme to help urlparse
            url = 'http://' + url
            
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        hostname = ext.domain + '.' + ext.suffix if ext.suffix else ext.domain
        path = parsed.path
        
        # Calculate features
        features = {}
        
        # 1. Length-based features
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)
        
        # 2. Count-based features
        features['count_digits'] = sum(c.isdigit() for c in url)
        features['count_letters'] = sum(c.isalpha() for c in url)
        features['count_special_chars'] = sum(1 for c in url if not c.isalnum())
        
        # Count specific suspicious patterns
        features['count_hyphen'] = url.count('-')
        features['count_at'] = url.count('@')
        features['count_question'] = url.count('?')
        features['count_equal'] = url.count('=')
        features['count_dot'] = url.count('.')
        features['count_percent'] = url.count('%')
        
        # 3. Structural & Semantic features
        features['has_ip'] = self._has_ip(url)
        features['entropy'] = self._entropy(url) if len(url) > 0 else 0
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        
        return features

    def get_feature_names(self):
        """Return the list of feature keys in consistent order."""
        # Run on a dummy URL to get the keys
        dummy_features = self.extract("http://example.com")
        return list(dummy_features.keys())

    def extract_array(self, url):
        """Return features as an ordered list (useful for scikit-learn)."""
        features = self.extract(url)
        return [features[k] for k in self.get_feature_names()]

if __name__ == '__main__':
    extractor = URLFeatureExtractor()
    print(extractor.extract("http://www.garage-pirenne.be/index.php?option=com_content"))
