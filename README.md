# Valknut

Valknut is an automated code security analyzer for GitHub repositories. It scans code changes in commits, compares them with a base of known malicious patterns, and uses an external LLM (such as LM Studio) to classify code as malicious, benign, or needing more context.

## Features

- **GitHub Integration:** Analyze any public or private repository by passing its URL or name.
- **Patch-based Analysis:** Only analyzes code additions in each commit.
- **Malicious Pattern Matching:** Uses a local database of suspicious code patterns for context.
- **LLM-powered Detection:** Sends code and context to an external Large Language Model (LLM) endpoint for classification.
- **Clear JSON Output:** Receives structured JSON responses indicating if code is malicious, the reason, and the tactic.

## Requirements

- Python 3.8+
- [chromadb](https://pypi.org/project/chromadb/)
- [PyGithub](https://pypi.org/project/PyGithub/)
- [requests](https://pypi.org/project/requests/)
- [dotenv](https://pypi.org/project/python-dotenv/) (optional, for loading environment variables)
- Access to a running LLM endpoint (e.g., [LM Studio](https://lmstudio.ai/))

## Installation

```bash
pip install chromadb PyGithub requests python-dotenv
```

## Usage

```bash
python main.py --repo <repo_url_or_name> --token <github_token> --model <model_name>
```

- `--repo`: GitHub repository URL (e.g., `https://github.com/org/repo`), `org/repo`, or just `repo` (will search by name).
- `--token`: Your GitHub personal access token.
- `--model`: The model name to use on the LLM endpoint (e.g., `deepseek-ai/DeepSeek-Coder-V2-Lite-Base`).

### Example

```bash
python main.py --repo https://github.com/example/myrepo --token ghp_xxx --model deepseek-ai/DeepSeek-Coder-V2-Lite-Base
```

## How It Works

1. **Repository Parsing:**  
   The tool accepts a GitHub URL, `org/repo`, or just a repo name. If only the name is provided, it searches GitHub for a match.

2. **Commit Scanning:**  
   For each commit, Valknut reads the patch and extracts only the added lines for each file.

3. **Pattern Context:**  
   The added code is compared against a local database of suspicious patterns (from the `badbase` folder).

4. **LLM Analysis:**  
   The code and context are sent to an external LLM endpoint (such as LM Studio) via HTTP POST.  
   The prompt instructs the LLM to return only a JSON object with:
   - `malicious`: true/false/"unknown"
   - `reason`: short explanation
   - `tactic`: tactic or technique (if malicious)
   - `needs_more_context`: true/false

5. **Results:**  
   Results are printed to the console, highlighting any detected malicious code.

## Configuration

- **LLM Endpoint:**  
  By default, Valknut sends requests to `http://localhost:1234/v1/chat/completions`.  
  You can change this in the code if your LLM endpoint differs.

- **Malicious Patterns:**  
  Add or edit suspicious code patterns in the `badbase` folder. Each `.txt` file is loaded as a separate collection.

## Example Output

```
📄 Analyzing main.py...
✅ No malicious code detected in main.py at 1234567
📄 Analyzing utils.py...
⚠️ Malicious code detected in utils.py at 89abcde
{
  "malicious": true,
  "reason": "Detected use of insecure deserialization.",
  "tactic": "Deserialization attack",
  "needs_more_context": false
}
```

## License

GNU AFFERO GENERAL PUBLIC LICENSE

---

**Note:**  
- Make sure your LLM endpoint is running and accessible.
- For private repositories, your GitHub token must have the correct scopes.