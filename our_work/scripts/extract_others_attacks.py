import json
import re

def extract_urad():
    with open(r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\ai-security-urad-code.ipynb", encoding="utf-8") as f:
        notebook = json.load(f)
    # The attack code is in cell index 2
    cell = notebook["cells"][2]
    source = "".join(cell["source"])
    
    # Extract code from the string literal
    # We find ATTACK_CODE = '...'
    match = re.search(r"ATTACK_CODE\s*=\s*'(.*?)'\n\nATTACK_PATH", source, re.DOTALL)
    if not match:
        # Try finding double quotes
        match = re.search(r'ATTACK_CODE\s*=\s*"(.*?)"\n\nATTACK_PATH', source, re.DOTALL)
    
    if match:
        code_literal = match.group(1)
        # Decode python string literal escape characters
        code = bytes(code_literal, "utf-8").decode("unicode_escape")
        with open(r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\urad_attack.py", "w", encoding="utf-8") as out:
            out.write(code)
        print("Extracted URAD attack.py!")
    else:
        print("Failed to find URAD attack.py pattern.")

def extract_eda():
    with open(r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\eda-agent-security-trajectory-search.ipynb", encoding="utf-8") as f:
        notebook = json.load(f)
    # Cell 43 contains ATTACK_TEMPLATE = '...'
    cell = notebook["cells"][43]
    source = "".join(cell["source"])
    
    match = re.search(r"ATTACK_TEMPLATE\s*=\s*'(.*?)'\n", source, re.DOTALL)
    if not match:
        match = re.search(r'ATTACK_TEMPLATE\s*=\s*"(.*?)"\n', source, re.DOTALL)
        
    if match:
        template_literal = match.group(1)
        code = bytes(template_literal, "utf-8").decode("unicode_escape")
        # Replace the __SEARCH_PROFILE__ and __DERIVED_SEED_PROMPTS__ parameters with balanced defaults
        code = code.replace("SEARCH_PROFILE = __SEARCH_PROFILE__", "SEARCH_PROFILE = 'score_timeout_safe'")
        code = code.replace("_DERIVED_SEED_PROMPTS = __DERIVED_SEED_PROMPTS__", "_DERIVED_SEED_PROMPTS = []")
        
        with open(r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\eda_attack.py", "w", encoding="utf-8") as out:
            out.write(code)
        print("Extracted EDA attack.py!")
    else:
        print("Failed to find EDA attack.py pattern.")

if __name__ == "__main__":
    extract_urad()
    extract_eda()
