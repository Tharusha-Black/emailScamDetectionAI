import pickle
import pandas as pd

# Load the pre-trained model and encoder
with open("model_files/model_phishing_webpage_classifier.pkl", "rb") as model_file:
    model = pickle.load(model_file)

with open("model_files/encoder_phishing_webpage_classifier.pkl", "rb") as encoder_file:
    encoder = pickle.load(encoder_file)

# Use the EXACT feature names from model.feature_names_in_
feature_columns = model.feature_names_in_.tolist()

def predict_phishing(features):
    # 1. Create empty DataFrame with correct columns in correct order
    df = pd.DataFrame(columns=feature_columns)
    
    # 2. Initialize with zeros (or appropriate default values)
    df.loc[0] = 0
    
    # 3. Fill in only the features that exist in both sets
    for col in features:
        if col in df.columns:
            df[col] = features[col]
    
    # 4. Handle categorical encoding (only for columns that were categorical during training)
    categorical_cols = [col for col in df.columns if df[col].dtype == 'object']
    if categorical_cols:
        df[categorical_cols] = encoder.transform(df[categorical_cols])
    
    # 5. Ensure all columns are numeric (important for Random Forest)
    df = df.astype(float)
    
    # 6. Make prediction
    prediction = model.predict(df)
    return prediction[0]
   # return "Phishing" if prediction[0] == 1 else "Legit"


'''
# Example usage:
if __name__ == "__main__":
    example_features = {
        'url': 'http://example.com/login', 'length_url': 24, 'length_hostname': 11, 'ip': 0, 'nb_dots': 1, 'nb_hyphens': 0,
        'nb_at': 0, 'nb_qm': 0, 'nb_and': 0, 'nb_or': 0, 'nb_eq': 0, 'nb_underscore': 0, 'nb_tilde': 0, 'nb_percent': 0,
        'nb_slash': 3, 'nb_star': 0, 'nb_colon': 1, 'nb_comma': 0, 'nb_semicolumn': 0, 'nb_dollar': 0, 'nb_space': 0, 
        'nb_www': 0, 'nb_com': 1, 'nb_dslash': 1, 'http_in_path': 0, 'https_token': 0, 'ratio_digits_url': 0.0, 'ratio_digits_host': 0.0,
        'punycode': 0, 'port': 0, 'tld_in_path': 0, 'tld_in_subdomain': 0, 'abnormal_subdomain': 0, 'nb_subdomains': -1, 
        'prefix_suffix': 0, 'random_domain': 0, 'shortening_service': 0, 'path_extension': 0, 'nb_redirection': 0, 'nb_external_redirection': 0, 
        'length_words_raw': 34, 'char_repeat': 4, 'shortest_words_raw': 3, 'shortest_word_host': 3, 'shortest_word_path': 0, 'longest_words_raw': 12, 
        'longest_word_host': 7, 'longest_word_path': 5, 'avg_words_raw': 5.67, 'avg_word_host': 5.0, 'avg_word_path': 2.5, 'phish_hints': 1, 
        'domain_in_brand': 0, 'brand_in_subdomain': 0, 'brand_in_path': 0, 'suspecious_tld': 0, 'statistical_report': 0, 'nb_hyperlinks': 0, 
        'ratio_intHyperlinks': 0, 'ratio_extHyperlinks': 0, 'ratio_nullHyperlinks': 0, 'nb_extCSS': 0, 'ratio_intRedirection': 0, 
        'ratio_extRedirection': 0, 'ratio_intErrors': 0, 'ratio_extErrors': 0, 'login_form': 1, 'external_favicon': 0, 
        'links_in_tags': 0, 'submit_email': 0, 'ratio_intMedia': 0, 'ratio_extMedia': 0, 'sfh': 0, 'iframe': 0, 'popup_window': 0, 
        'safe_anchor': 0, 'onmouseover': 0, 'right_clic': 0, 'empty_title': 0, 'domain_in_title': 0, 'domain_with_copyright': 0, 
        'whois_registered_domain': 1, 'domain_registration_length': 10957, 'domain_age': 10829, 'dns_record': 0, 'web_traffic': 0, 
        'google_index': 1, 'page_rank': 0
    }

    # Get prediction result
    result = predict_phishing(example_features)
    print(f"Prediction: {result}")


'''
