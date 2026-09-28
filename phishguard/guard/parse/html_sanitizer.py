from bs4 import BeautifulSoup

def sanitize_html(html_content: str) -> str:
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Remove scripts, styles
    for script in soup(["script", "style"]):
        script.extract()
    
    return soup.get_text(separator=' ')

def get_hidden_text(html_content: str) -> str:
    if not html_content:
        return ""
    # Very simplified hidden text extraction, looking for display:none
    # In a real impl, this would parse CSS more carefully
    soup = BeautifulSoup(html_content, 'html.parser')
    hidden_elements = soup.find_all(style=lambda value: value and 'display:none' in value.replace(' ', '').lower())
    return " ".join([el.get_text() for el in hidden_elements])
