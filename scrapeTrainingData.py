
#Web scraping scripts to extract training examples from various sources for use in AI model training.
#Install required packages: pip install requests beautifulsoup4 selenium lxml
#!!V0.1!!
#Legacy Script do not use#

import requests
from bs4 import BeautifulSoup 
import json
import time
from pathlib import Path
import urllib.robotparser
import urllib.parse


def check_robots_txt(url):
    #Check if scraping is allowed by robots.txt
    try:
        rp = urllib.robotparser.RobotFileParser()
        base_url = urllib.parse.urljoin(url, '/robots.txt')
        rp.set_url(base_url)
        rp.read()
        
        # Check if our user agent can fetch this URL
        can_fetch = rp.can_fetch("*", url)
        if not can_fetch:
            print(f"  ⚠ robots.txt disallows scraping: {url}")
        return can_fetch
    except Exception as e:
        # If we can't check robots.txt, assume it's okay but warn
        print(f"  ⚠ Could not check robots.txt for {url}: {e}")
        return True


def scrape_owasp_sql_injection():
    #Scrape OWASP SQL Injection examples
    print("[*] Scraping OWASP SQL Injection Prevention...")
    
    url = "https://owasp.org/www-community/attacks/SQL_Injection"
    
    # Check robots.txt
    if not check_robots_txt(url):
        print("✗ Skipped: robots.txt disallows scraping")
        return False
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find all code blocks and text
        examples = []
        
        # Extract main content
        content = soup.find('div', class_='main-content') or soup.find('article')
        if not content:
            content = soup.body
        
        # Get all paragraphs and code blocks
        paragraphs = content.find_all(['p', 'pre', 'code'])
        
        current_example = []
        for para in paragraphs:
            text = para.get_text(strip=True)
            if text:
                current_example.append(text)
        
        # Save raw text
        output = "\n\n".join(current_example)
        with open("raw-examples/owasp-sql-injection.txt", "w", encoding="utf-8") as f:
            f.write(output)
        
        print(f"✓ Saved OWASP SQL Injection (~{len(output)} characters)")
        return True
    
    except Exception as e:
        print(f"✗ Error scraping OWASP: {e}")
        return False

def scrape_owasp_input_validation():
    """Scrape OWASP Input Validation examples"""
    print("[*] Scraping OWASP Input Validation...")
    
    url = "https://owasp.org/www-community/attacks/Command_Injection" #This is the URL the script will check, change as needed
    
    # Check robots.txt
    if not check_robots_txt(url):
        print("✗ Skipped: robots.txt disallows scraping")
        return False
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        content = soup.find('div', class_='main-content') or soup.body
        paragraphs = content.find_all(['p', 'pre', 'code', 'h2', 'h3'])
        
        current_example = []
        for para in paragraphs:
            text = para.get_text(strip=True)
            if text:
                current_example.append(text)
        
        output = "\n\n".join(current_example)
        with open("raw-examples/owasp-input-validation.txt", "w", encoding="utf-8") as f:
            f.write(output)
        
        print(f"✓ Saved OWASP Input Validation (~{len(output)} characters)")
        return True
    
    except Exception as e:
        print(f"✗ Error scraping OWASP Input Validation: {e}")
        return False

# 3. STACKOVERFLOW - High-voted secure coding Q&A

def scrape_stackoverflow_security():
    """Scrape StackOverflow Python security Q&A"""
    print("[*] Scraping StackOverflow security answers...")
    
    # Using StackExchange API (no authentication required for basic queries)
    url = "https://api.stackexchange.com/2.3/search/advanced" #This is the URL the script will check, change as needed
    
    params = {
        'order': 'desc',
        'sort': 'votes',
        'q': 'python sql injection prevention',
        'tagged': 'python;security',
        'site': 'stackoverflow',
        'pagesize': 10
    }
    
    try:
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        examples = []
        for item in data.get('items', []):
            examples.append(f"\n# Question: {item['title']}")
            examples.append(f"Score: {item['score']}")
            examples.append(f"URL: {item['link']}\n")
        
        with open("raw-examples/stackoverflow-security.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(examples))
        
        print(f"✓ Saved StackOverflow examples ({len(examples)} questions)")
        return True
    
    except Exception as e:
        print(f"✗ Error scraping StackOverflow: {e}")
        return False


# PyPI - Read secure coding library documentation


def scrape_pypi_security_libs():
    """Scrape PyPI security library documentation"""
    print("[*] Scraping PyPI security libraries...")
    
    # Check robots.txt
    if not check_robots_txt("https://pypi.org/"): #This is the URL the script will check, change as needed
        print("✗ Skipped: robots.txt disallows scraping PyPI")
        return False
    
    # Security-focused Python libraries
    libs = [
        "paramiko",  # Secure SSH
        "cryptography",  # Encryption
        "bleach",  # HTML sanitization
    ]
    
    all_content = []
    
    for lib in libs:
        try:
            url = f"https://pypi.org/project/{lib}/"
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Get description
            description = soup.find('div', class_='description')
            if description:
                all_content.append(f"\n# {lib} - PyPI\n")
                all_content.append(description.get_text())
            
            time.sleep(1)
        
        except Exception as e:
            print(f"  ✗ Could not fetch {lib}: {e}")
    
    if all_content:
        with open("raw-examples/pypi-security-libs.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(all_content))
        print(f"✓ Saved PyPI library docs (~{len(''.join(all_content))} characters)")
        return True
    else:
        print("✗ No PyPI content found")
        return False


# MAIN RUNNER


def main():
    """Run all scrapers"""
    print("=" * 60)
    print("Training Data Web Scraper")
    print("=" * 60)
    
    # Create output directory
    Path("raw-examples").mkdir(exist_ok=True)
    
    results = []
    
    # Run all scrapers
    # All sources are authorized and permit scraping for educational purposes
    print("\n[Phase 1: OWASP] - Educational resource (explicitly allows scraping)")
    results.append(("OWASP SQL Injection", scrape_owasp_sql_injection()))
    results.append(("OWASP Input Validation", scrape_owasp_input_validation()))
    
    print("\n[Phase 2: StackOverflow] - Uses official StackExchange API (authorized)")
    results.append(("StackOverflow Security", scrape_stackoverflow_security()))
    
    print("\n[Phase 3: PyPI Libraries] - Official package index (authorized)")
    results.append(("PyPI Security Libs", scrape_pypi_security_libs()))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, success in results:
        status = "✓" if success else "✗"
        print(f"{status} {name}")
    
    print("\nAll raw examples saved to: raw-examples/")
    print("Convert to JSONL format")
    print(f"\nOutput path: {Path('raw-examples').resolve()}")

if __name__ == "__main__":
    main()

##EOF##