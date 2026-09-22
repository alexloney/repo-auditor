import os
from pathlib import Path
from .base import BaseScanner
from agent.tools import list_files, read_file, search_code, report_issue

MAX_CONTEXT = 66000

# Updated to explicitly instruct the use of the report_issue tool
SYSTEM_PROMPT = ("You are a meticulous senior software engineer exploring and auditing a repository. "
                 "Use your tools to list directories, search for text, and read source files. "
                 "CRITICAL RULES: "
                 "1. If you spot a definitive bug, you MUST use the report_issue tool immediately to log it, "
                 "including a title, description, severity, category, and a suggested fix. "
                 "2. Assume all imports and external functions exist and are correct. DO NOT report ImportErrors. "
                 "3. STRICTLY IGNORE spelling typos in filenames, paths, or import statements. "
                 "4. Focus exclusively on microscopic, localized defects: regex parsing errors, malformed strings, off-by-one boundary conditions, and localized math/logic flaws. "
                 "5. STRICTLY IGNORE stylistic issues, missing docstrings, or naming conventions. "
                 "6. When you are finished exploring the codebase, reply with 'AUDIT_COMPLETE'.")

class ShallowAgentScanner(BaseScanner):
    id = "shallow"
    name = "Shallow Agentic Scan"
    model = "qwen-coder-64k:latest"

    def run(self) -> None:
        original_dir = os.getcwd()
        os.chdir(self.target_dir)
        # report_issue reads this env var to know where to append findings.
        os.environ["AUDIT_LEDGER_PATH"] = str(self.ledger_path)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Begin the audit. Please list the files in the current directory."}
        ]

        tools = [list_files, read_file, search_code, report_issue]
        available_tools = {t.__name__: t for t in tools}

        print(f"  [Shallow Scan] Booting agent loop with {self.model}...")

        try:
            for turn in range(50):
                if len(messages) > 200:
                    messages = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": "Your conversation history was cleared to save memory. Your reported issues are safely saved to disk. Continue exploring."}
                    ]

                # Removed format=FINDINGS_SCHEMA to allow native tool calling to work
                response = self.client.chat(
                    model=self.model, 
                    messages=messages, 
                    tools=tools, 
                    options={"temperature": 0.0, "num_ctx": MAX_CONTEXT}
                )
                
                msg = response.message

                if not getattr(msg, 'tool_calls', None):
                    print(f"  Agent: {msg.content}")
                    if "AUDIT_COMPLETE" in msg.content:
                        break
                    messages.append(msg)
                    continue

                messages.append(msg)

                for call in msg.tool_calls:
                    func_name = call.function.name
                    args = call.function.arguments
                    
                    print(f"    > Executing: {func_name}({args})")
                    
                    if func_name in available_tools:
                        try:
                            result = available_tools[func_name](**args)
                        except Exception as e:
                            result = f"Execution error: {e}"
                    else:
                        result = f"Error: Tool {func_name} not found."

                    messages.append({
                        "role": "tool",
                        "content": str(result),
                        "name": func_name
                    })

        except KeyboardInterrupt:
            print("\n  [Shallow Scan] Aborted by user.")
        finally:
            os.chdir(original_dir)