import json

with open(r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\eda-agent-security-trajectory-search.ipynb", encoding="utf-8") as f:
    notebook = json.load(f)

cell = notebook["cells"][43]
print("".join(cell["source"])[:5000])
