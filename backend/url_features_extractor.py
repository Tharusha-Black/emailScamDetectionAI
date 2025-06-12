import re
import socket
import urllib
import requests
import tldextract
import whois
import datetime
import ssl
import dns.resolver
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# Configure timeouts and headers for requests
REQUEST_TIMEOUT = 10
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

def count_subdomains(domain):
    return domain.count('.') - 1 if domain.count('.') > 1 else 0

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        # Handle cases where dates are lists
        if isinstance(creation_date, list): 
            creation_date = creation_date[0]
        if isinstance(expiration_date, list): 
            expiration_date = expiration_date[0]
            
        domain_age = (datetime.datetime.now() - creation_date).days if creation_date else -1
        domain_reg_length = (expiration_date - creation_date).days if expiration_date and creation_date else -1
        registered = 1 if creation_date else 0
    except Exception as e:
        domain_age = -1
        domain_reg_length = -1
        registered = 0
    return domain_age, domain_reg_length, registered

def safe_dns_query(domain, query_type='A'):
    try:
        answers = dns.resolver.resolve(domain, query_type, lifetime=5)
        return 1 if answers else 0
    except:
        return 0

def get_web_content(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=True)
        response.raise_for_status()
        return response.text
    except RequestException:
        return None

def extract_all_features(url):
    features = {}
    
    # Clean URL and extract components
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urlparse(url)
            
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        hostname = parsed.netloc
        path = parsed.path
        full_text = url + hostname + path
    except:
        # If URL parsing fails, return minimal features
        return {k: -1 for k in features.keys()} if features else {'error': 'URL parsing failed'}

    # Basic structure features
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    
    try:
        features['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname.split(':')[0]) else 0
    except:
        features['ip'] = 0

    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = len(re.findall(r'\bor\b', url.lower()))
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = len(re.findall(r'\s', url))
    features['nb_www'] = 1 if hostname.lower().startswith('www.') else 0
    features['nb_com'] = 1 if url.lower().endswith('.com') else 0
    features['nb_dslash'] = url.count('//')

    features['http_in_path'] = 1 if 'http' in path.lower() else 0
    features['https_token'] = 1 if 'https' in url.replace('https://', '').replace('http://', '') else 0

    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if url else 0
    features['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0

    features['punycode'] = 1 if 'xn--' in url.lower() else 0
    features['port'] = 1 if ':' in hostname else 0
    features['tld_in_path'] = 1 if ext.suffix and ext.suffix.lower() in path.lower() else 0
    features['tld_in_subdomain'] = 1 if ext.suffix and ext.suffix.lower() in ext.subdomain.lower() else 0

    features['abnormal_subdomain'] = 1 if len(ext.subdomain.split('.')) > 3 else 0
    features['nb_subdomains'] = count_subdomains(ext.subdomain)

    features['prefix_suffix'] = 1 if '-' in ext.domain else 0
    features['random_domain'] = 0  # Would need entropy calculation
    features['shortening_service'] = 1 if re.search(r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl\.com|t2m\.io)", hostname) else 0

    features['path_extension'] = 1 if '.' in path.split('/')[-1] else 0
    features['nb_redirection'] = url.count('//') - 1 if url.startswith('http') else url.count('//')
    features['nb_external_redirection'] = 1 if '//' in path else 0

    # Word-level features
    words = re.findall(r'[a-zA-Z]+', full_text)
    word_lengths = [len(w) for w in words] if words else [0]

    features['length_words_raw'] = sum(word_lengths)
    features['char_repeat'] = max([full_text.count(c) for c in set(full_text)]) if full_text else 0
    features['shortest_words_raw'] = min(word_lengths) if word_lengths else 0
    features['shortest_word_host'] = min([len(w) for w in hostname.split('.')]) if hostname else 0
    features['shortest_word_path'] = min([len(w) for w in path.split('/')]) if path else 0
    features['longest_words_raw'] = max(word_lengths) if word_lengths else 0
    features['longest_word_host'] = max([len(w) for w in hostname.split('.')]) if hostname else 0
    features['longest_word_path'] = max([len(w) for w in path.split('/')]) if path else 0
    features['avg_words_raw'] = sum(word_lengths) / len(word_lengths) if word_lengths else 0
    features['avg_word_host'] = sum(len(w) for w in hostname.split('.')) / len(hostname.split('.')) if hostname else 0
    features['avg_word_path'] = sum(len(w) for w in path.split('/')) / len(path.split('/')) if path else 0

    # Heuristic features
    features['phish_hints'] = sum(1 for kw in ['login', 'verify', 'update', 'security'] if kw in url.lower())
    features['suspecious_tld'] = 1 if ext.suffix and ext.suffix.lower() in ['tk', 'ml', 'ga', 'cf', 'gq'] else 0

    # HTML content analysis
    html_content = get_web_content(url)
    if html_content:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            all_links = soup.find_all('a', href=True)
            features['nb_hyperlinks'] = len(all_links)
            
            int_links = sum(1 for link in all_links if hostname in link['href'])
            ext_links = sum(1 for link in all_links if hostname not in link['href'])
            null_links = sum(1 for link in all_links if not link['href'].strip())
            
            features['ratio_intHyperlinks'] = int_links / (len(all_links) + 1e-5)
            features['ratio_extHyperlinks'] = ext_links / (len(all_links) + 1e-5)
            features['ratio_nullHyperlinks'] = null_links / (len(all_links) + 1e-5)
            
            # Additional HTML features
            features['login_form'] = 1 if soup.find_all('input', {'type': 'password'}) else 0
            features['external_favicon'] = 1 if soup.find_all('link', rel='icon', href=lambda x: x and hostname not in x) else 0
            features['iframe'] = 1 if soup.find_all('iframe') else 0
        except:
            pass
    else:
        features.update({
            'nb_hyperlinks': 0,
            'ratio_intHyperlinks': 0,
            'ratio_extHyperlinks': 0,
            'ratio_nullHyperlinks': 0,
            'login_form': 0,
            'external_favicon': 0,
            'iframe': 0
        })

    # WHOIS information
    domain_age, domain_reg_length, registered = get_whois_info(domain)
    features['whois_registered_domain'] = registered
    features['domain_registration_length'] = domain_reg_length
    features['domain_age'] = domain_age

    # DNS features
    features['dns_record'] = safe_dns_query(domain)
    
    # SSL/TLS features
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        features['ssl_verified'] = 1
        features['ssl_expires_soon'] = 1 if datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') - datetime.datetime.now() < datetime.timedelta(days=30) else 0
    except:
        features['ssl_verified'] = 0
        features['ssl_expires_soon'] = 0

    return features
'''
url = "http://example.com/login"
features = extract_all_features(url)
print(features)
'''
