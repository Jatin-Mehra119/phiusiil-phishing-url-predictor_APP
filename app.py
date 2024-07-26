import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import joblib
import pandas as pd

# Function to extract TLD
def extract_tld(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    tld = domain.split('.')[-1] 
    return tld

# URL fetch function
def url_fetch(url):
    # Fetch the content
    response = requests.get(url)
    html = response.text

    # URL Length
    url_length = len(url)

    # Domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_length = len(domain)

    # Check if HTTPS
    is_https = url.startswith('https://')

    # Parse HTML
    soup = BeautifulSoup(html, 'html.parser')

    # Title
    has_title = bool(soup.title)
    title = soup.title.string if has_title else None

    # No. of Images
    no_of_images = len(soup.find_all('img'))

    # No. of CSS
    no_of_css = len(soup.find_all('link', {'rel': 'stylesheet'}))

    # No. of JS
    no_of_js = len(soup.find_all('script'))

    # Count external references
    def count_external_references(soup, domain):
        external_references = 0
        for link in soup.find_all('a', href=True):
            href = link['href']
            href_parsed = urlparse(href)
            href_domain = href_parsed.netloc
            if href_domain and href_domain != domain:
                external_references += 1
        return external_references

    no_of_external_references = count_external_references(soup, domain)

    return url_length, domain, domain_length, is_https, has_title, title, no_of_images, no_of_css, no_of_js, no_of_external_references

# Load the model
model = joblib.load('phishing_url_pipeline.pkl')

st.title('Phishing URL Detection')

# Input URL from the user
url = st.text_input("Enter the URL to be analyzed:")

if st.button('Analyze'):
    st.write('The URL is being analyzed...')
    st.write('Please wait...')
    if url:
        try:
            url_length, domain, domain_length, is_https, has_title, title, no_of_images, no_of_css, no_of_js, no_of_external_references = url_fetch(url)
        except Exception as e:
            st.write("An error occurred while fetching the URL. Please try again.") # Display error message
            st.stop()
        # Extract TLD
        tld = extract_tld(url)

        # Prepare input for the model
        input_data = {
            "URLLength": url_length,
            "Domain": domain,
            "DomainLength": domain_length,
            "IsHTTPS": int(is_https),
            "HasTitle": int(has_title),
            "Title": title,
            "NoOfImage": no_of_images,
            "NoOfCSS": no_of_css,
            "NoOfJS": no_of_js,
            "NoOfExternalRef": no_of_external_references,
            "TLD": tld
        }

        # Convert to DataFrame
        input_df = pd.DataFrame([input_data])

        # Make prediction
        prediction = model.predict(input_df)

        # Display results
        if prediction[0] == 1:
            st.write("The URL is classified as Safe.")
        else:
            st.write("The URL is classified as phishing.")
    else:
        st.write("Please enter a URL to analyze.")