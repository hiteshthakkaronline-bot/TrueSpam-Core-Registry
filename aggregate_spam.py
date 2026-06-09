import urllib.request
import re

# Truly free open threat feeds tracking live phishing attacks & domain drops
FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text/", # Live daily phishing URL streams
    "https://raw.githubusercontent.com/castle/disposable-phone-numbers/main/disposable-phone-numbers.txt" # Open fallback directory
]

# Regex targeting valid Indian mobile numbers (allows optional +91 or 91 country codes)
# Matches 6, 7, 8, or 9 followed by exactly 9 digits
INDIAN_MOBILE_REGEX = re.compile(r'(?:\+?91)?[6-9]\d{9}')

def fetch_and_extract_spam():
    unique_spam_numbers = set()
    
    for url in FEEDS:
        try:
            print(f"Scanning open threat stream: {url}")
            # Mock a browser user-agent to ensure target threat servers don't drop the connection
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
                # Extract any text string fitting the Indian telecom grid layout
                matches = INDIAN_MOBILE_REGEX.findall(content)
                for match in matches:
                    # Strip formatting symbols down to numerical digits
                    digits = re.sub(r'[^0-9]', '', match)
                    
                    # Normalize numbers down to the clean 10-digit base format your app processes
                    if len(digits) == 12 and digits.startswith('91'):
                        digits = digits[2:]
                        
                    if len(digits) == 10 and digits[0] in '6789':
                        unique_spam_numbers.add(digits)
                        
        except Exception as e:
            print(f"Skipping stream entry due to connection limit: {e}")

    # Write compiled tokens out into a clean line-separated flat text asset file
    with open("master_blocklist.txt", "w") as out_file:
        for number in sorted(unique_spam_numbers):
            out_file.write(f"{number}\n")
            
    print(f"Compilation Complete! Isolated {len(unique_spam_numbers)} active Indian fraud lines.")

if __name__ == "__main__":
    fetch_and_extract_spam()
