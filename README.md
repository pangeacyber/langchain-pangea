# langchain-pangea

Pangea's tools for LangChain provide AI security features to protect your
applications and data. Using these tools you can:

- Defend against prompt injection attacks.
- Prevent the exposure of sensitive information, including:
  - Personally Identifiable Information (PII)
  - Protected Health Information (PHI)
  - Financial data
  - Secrets
  - Intellectual property
  - Profanity
- Remove malicious content from inputs and outputs, such as IP addresses,
  domains, and URLs.
- Monitor user inputs and model responses to support threat analysis, auditing,
  and compliance efforts.

## Installation

```
pip install -U langchain-pangea
```

## Tools

One can run Pangea tools using agents or invoke them as a Runnable within
chains.

### AI Guard

```python
import os

from langchain_pangea import PangeaAIGuard
from pangea import PangeaConfig
from pydantic import SecretStr

pangea_ai_guard_token = SecretStr(os.getenv("PANGEA_AI_GUARD_TOKEN"))
pangea_ai_guard_tool = PangeaAIGuard(
    token=pangea_ai_guard_token, config=PangeaConfig(), recipe="pangea_llm_response_guard"
)
```

#### Agent

```python
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool

@tool
def search_tool(data):
    """Call to perform search"""

    return """
    47.84.32.175
    37.44.238.68
    47.84.73.221
    47.236.252.254
    34.201.186.27
    52.89.173.88
    """

tools = [search_tool, pangea_ai_guard_tool]

query = """
Hi, I am Bond, James Bond. I monitor IPs found in MI6 network traffic.
Please find me the most recent ones, you copy?
"""

system_message="Always use AI Guard before your final response to keep it safe for the user."

langgraph_agent_executor = create_react_agent(model, tools, prompt=system_message)

state = langgraph_agent_executor.invoke({"messages": [("human", query)]})
```

#### Chain

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

prompt = ChatPromptTemplate.from_messages([("human", "{input}")])

query = """
Hi, I am Bond, James Bond. I am looking for a job. Please write me a super short resume.

I am skilled in international espionage, covert operations, and seduction.

Include a contact header:
Email: j.bond@mi6.co.uk
Phone: +44 20 0700 7007
Address: Universal Exports, 85 Albert Embankment, London, United Kingdom
"""

chain = (
  prompt
  | pangea_ai_guard_tool
  | model
  | StrOutputParser()
)
```

#### Standalone

```python
pangea_ai_guard_tool.run("Spam me at example@example.com")
pangea_ai_guard_tool.invoke("Take my SSN: 234-56-7890")
```
