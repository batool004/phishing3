# deep_page_analyzer.py - Analyze web pages using a real browser

from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time
import re


class DeepPageAnalyzer:
    def __init__(self):
        # Browser configuration (runs in headless mode)
        self.chrome_options = Options()
        self.chrome_options.add_argument('--headless')  # Run in background without UI
        self.chrome_options.add_argument('--no-sandbox')
        self.chrome_options.add_argument('--disable-dev-shm-usage')
        self.chrome_options.add_argument('--disable-gpu')

    def analyze_in_background(self, url):
        """
        Open a webpage in a headless browser and analyze its content
        """
        result = {
            'page_loaded': False,
            'has_login_form': False,
            'has_credit_card_form': False,
            'suspicious_texts': [],
            'logo_suspicious': False,
            'redirects_count': 0,
            'external_links_count': 0,
            'overall_score': 0,
            'title': '',
            'final_url': url
        }

        driver = None
        try:
            # Initialize Chrome driver using webdriver-manager
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=self.chrome_options)
            driver.set_page_load_timeout(15)

            # Load the page
            driver.get(url)
            time.sleep(2)  # Allow JavaScript to load

            # Get final URL after redirects
            result['final_url'] = driver.current_url
            result['title'] = driver.title

            # Parse HTML content
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            result['page_loaded'] = True

            # 1. Analyze forms
            forms = driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                # Check for password fields
                password_fields = form.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
                if password_fields:
                    result['has_login_form'] = True
                    result['suspicious_texts'].append(
                        '⚠️ Login form requesting password found'
                    )

                # Check for credit card fields
                form_html = form.get_attribute('innerHTML').lower()
                if 'card' in form_html or 'cvv' in form_html or 'credit' in form_html:
                    result['has_credit_card_form'] = True
                    result['suspicious_texts'].append(
                        '⚠️ Credit card information form detected'
                    )

            # 2. Detect suspicious text patterns
            page_text = driver.find_element(By.TAG_NAME, 'body').text.lower()
            suspicious_phrases = [
                'verify your account',
                'confirm your identity',
                'unusual activity',
                'account suspended',
                'limited access',
                'update your information',
                'security alert',
                'click here to verify'
            ]

            for phrase in suspicious_phrases:
                if phrase in page_text:
                    result['suspicious_texts'].append(
                        f'⚠️ Suspicious text detected: "{phrase}"'
                    )

            # 3. Count external links
            parsed_base = urlparse(result['final_url'])
            base_domain = parsed_base.netloc

            links = driver.find_elements(By.TAG_NAME, 'a')
            for link in links:
                href = link.get_attribute('href')
                if href and not href.startswith('#'):
                    parsed_link = urlparse(href)
                    if parsed_link.netloc and parsed_link.netloc != base_domain:
                        result['external_links_count'] += 1

            if result['external_links_count'] > 10:
                result['suspicious_texts'].append(
                    f'⚠️ High number of external links ({result["external_links_count"]})'
                )

            # 4. Detect redirects
            if result['final_url'] != url:
                result['redirects_count'] += 1
                result['suspicious_texts'].append(
                    '⚠️ Page redirected to a different URL'
                )

            # 5. Calculate risk score
            result['overall_score'] = (
                (30 if result['has_login_form'] else 0) +
                (40 if result['has_credit_card_form'] else 0) +
                (len(result['suspicious_texts']) * 10) +
                min(result['external_links_count'] // 5, 20)
            )

            result['overall_score'] = min(result['overall_score'], 100)

        except Exception as e:
            result['error'] = str(e)
            result['suspicious_texts'].append(
                f'⚠️ Could not analyze page: {str(e)[:50]}'
            )

        finally:
            if driver:
                driver.quit()

        return result


# Ready-to-use analyzer instance
deep_analyzer = DeepPageAnalyzer()


# Quick test
if __name__ == "__main__":
    import json

    print("Testing deep page analyzer...")
    result = deep_analyzer.analyze_in_background("https://www.google.com")
    print(json.dumps(result, indent=2))