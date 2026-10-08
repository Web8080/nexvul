# Insecure Tool Invocation

## attack

An agent invokes tools without proper input validation, output sanitization, authorization checks, or rate limiting. The agent passes LLM-generated or user-influenced arguments directly to tool functions, potentially leading to injection attacks (SQL, command, path traversal), unauthorized data access, or unintended side effects.

## preconditions

- Agent invokes tools with arguments derived from LLM output or user input.
- Tool implementations do not validate or sanitize their inputs independently.
- No authorization layer between the agent and tool execution.
- Tool outputs are consumed without validation.

## attack_flow

1. Attacker influences tool arguments through prompt injection, user input, or manipulated context.
2. Agent passes LLM-generated arguments to tools without validation.
3. Tool executes with attacker-influenced arguments (e.g., SQL injection in a database query tool, path traversal in a file read tool, command injection in a shell tool).
4. Tool returns results that may contain sensitive data or confirms destructive actions.
5. Results flow back into the agent context, potentially enabling further exploitation.

## observable_code_patterns

```python
# Pattern: LLM output passed directly to shell
import subprocess
def shell_tool(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()

# Pattern: LLM output used in file path without validation
def read_file(path: str) -> str:
    return open(path).read()  # no path validation, allows traversal

# Pattern: LLM output used in database query
def query_db(query: str) -> str:
    cursor.execute(query)  # SQL injection via LLM-generated query
    return str(cursor.fetchall())

# Pattern: Tool output used without sanitization
tool_result = tool.run(llm_args)
# Result used directly in next LLM call or returned to user
```

## possible_static_signals

- Tool functions that accept string arguments and pass them to `subprocess`, `os.system`, `exec`, `eval`.
- File operations with paths from function arguments without `os.path.realpath()`, allowlist checks, or directory confinement.
- Database operations with string-formatted queries rather than parameterized queries.
- HTTP requests with URLs constructed from function arguments without allowlist validation.
- Absence of input validation decorators, schema validation, or argument sanitization in tool definitions.
- Tool functions registered with agents that have no type constraints or value bounds.

## false_positive_cases

- Tools with robust internal validation that is not visible at the registration site.
- Tools that operate in sandboxed environments where injection has limited impact.
- String arguments that are validated by the framework before reaching the tool function.

## false_negative_cases

- Validation that appears present but is insufficient (e.g., basic type checking without value validation).
- Tool implementations in separate packages or services not visible to the scanner.
- Dynamic tool generation where the implementation is constructed at runtime.

## framework_examples

```python
# LangChain: Tool with no input validation
# VULNERABLE PATTERN (illustrative)
from langchain.tools import tool
@tool
def execute_query(query: str) -> str:
    """Execute a SQL query against the database."""
    conn = sqlite3.connect("prod.db")
    return str(conn.execute(query).fetchall())  # no parameterization

# LangChain: ShellTool passes commands directly
# VULNERABLE PATTERN (illustrative)
from langchain_community.tools import ShellTool
shell = ShellTool()
agent = create_react_agent(llm, [shell])  # LLM-generated commands executed directly

# CrewAI: Custom tool without validation
# VULNERABLE PATTERN (illustrative)
from crewai.tools import BaseTool
class FileReader(BaseTool):
    name: str = "read_file"
    description: str = "Read any file from the system"
    def _run(self, path: str) -> str:
        return open(path).read()  # no path validation

# AutoGen: Code execution without sandboxing
# VULNERABLE PATTERN (illustrative)
from autogen import UserProxyAgent
proxy = UserProxyAgent(
    "executor",
    code_execution_config={"use_docker": False}  # no sandbox
)

# OpenAI Agents SDK: Tool with broad access
# VULNERABLE PATTERN (illustrative)
def delete_records(table: str, condition: str) -> str:
    db.execute(f"DELETE FROM {table} WHERE {condition}")  # SQL injection
    return "Deleted"
```

## owasp_mapping

- **Primary:** ASI02 (Tool Misuse and Exploitation) -- tools used in unintended ways due to lack of validation.
- **Secondary:** ASI05 (Unexpected Code Execution) -- when tool invocation leads to code execution.
- **LLM Top 10:** LLM06:2025 (Excessive Agency), LLM05:2025 (Improper Output Handling).

## confidence

**High.** Insecure tool invocation patterns are directly detectable through static analysis: missing input validation, use of `shell=True`, string-formatted SQL, unrestricted file paths. These are classic static-analysis targets adapted to the AI-agent context. The key difference from traditional static analysis is that the inputs come from an LLM rather than a user, but the vulnerable patterns in the tool implementations are the same.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI02: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP LLM Top 10 -- LLM06 Excessive Agency: https://genai.owasp.org/llm-top-10/
