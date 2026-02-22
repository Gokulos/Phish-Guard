import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import math
from collections import Counter
from Data_Phish_NonPhish import merged_data

df = merged_data()

def calculate_entropy(text):
    if not text: return 0
    counter = Counter(str(text))
    probs = [count / len(text) for count in counter.values()]
    return -sum(p * math.log2(p) for p in probs)

def get_url_features(url, label):
    url = str(url)
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    # 1. Length & Basic Counts
    features = {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscore': url.count('_'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special_chars': len(re.findall(r'[!@#$%^&*(),.?":{}|<>+]', url)),
        'num_parameters': len(query.split('&')) if query else 0,
    }

    # 2. Domain & TLD Features
    subdomains = hostname.split('.')
    features['num_subdomains'] = max(0, len(subdomains) - 2)
    features['has_ip_in_domain'] = 1 if re.search(r'\d{1,3}\.\d{1,3}', hostname) else 0
    features['tld_length'] = len(subdomains[-1]) if subdomains else 0
    features['has_port'] = 1 if ":" in hostname else 0
    features['has_punycode'] = 1 if "xn--" in url else 0
    
    # 3. Structural Flags
    shorteners = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl'
    features['is_shortened_url'] = 1 if re.search(shorteners, url) else 0
    features['has_at_symbol'] = 1 if "@" in url else 0
    features['has_redirect'] = 1 if url.count('//') > 1 else 0
    features['has_double_slash_path'] = 1 if "//" in path else 0
    
    # 4. Protocol & Security
    features['has_https'] = 1 if parsed.scheme == 'https' else 0
    features['https_in_domain'] = 1 if 'https' in hostname else 0
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.cfd'] # Added .cfd based on your example
    features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
    
    # 5. Statistical & Content
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(hostname)
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
    
    tokens = re.split(r'\W+', url)
    token_lengths = [len(t) for t in tokens if t]
    features['avg_token_length'] = np.mean(token_lengths) if token_lengths else 0
    features['max_token_length'] = max(token_lengths) if token_lengths else 0
    
    # 6. Brand Indicators
    # phishing websites often contains these in their submains like, "allegro.pl-aukcja" or something
    brands = ['google', 'facebook', 'amazon', 'netflix', 'paypal', 'apple', 'allegro', 'microsoft']
    features['contains_known_brand'] = 1 if any(b in url.lower() for b in brands) else 0
    features['brand_in_subdomain'] = 1 if any(b in hostname.lower() for b in brands) else 0
    features['brand_in_path'] = 1 if any(b in path.lower() for b in brands) else 0
    features['label'] = label

    features['num_letters'] = sum(c.isalpha() for c in url)
    features['letter_ratio'] = features['num_letters'] / len(url)
    features['special_char_ratio'] = features['num_special_chars'] / len(url)
    features['uppercase_ratio'] = sum(c.isupper() for c in url) / len(url)

    features['subdomain_depth'] = hostname.count('.') 

    features['brand_mismatch'] = 1 if (
        any(b in url.lower() for b in brands) and
        not any(b in subdomains[-2] for b in brands)
        ) else 0
    suspicious_words = [
    'login', 'verify', 'update', 'secure', 
    'account', 'confirm', 'bank', 'signin', 'wp'
                ]

    features['num_suspicious_words'] = sum(
        1 for w in suspicious_words if w in url.lower()
    )
    features['path_to_url_ratio'] = len(path) / len(url)
    features['hostname_to_url_ratio'] = len(hostname) / len(url)
    features['path_entropy'] = calculate_entropy(path)
    features['query_entropy'] = calculate_entropy(query)
    
    return features

print("Extracting features from dataset...")
extracted_data = [get_url_features(row['url'], row['label']) for _, row in df.iterrows()]
final_df = pd.DataFrame(extracted_data)
print(final_df.head())
