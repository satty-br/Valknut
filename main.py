import os
import argparse
import re
from github import Github
from dotenv import load_dotenv
import requests

from bad_base_loader import BadBaseLoader

class ValknutAnalyzer:
    def __init__(self, repo, github_token,model):
        self.github_token = github_token
        self.client = BadBaseLoader().get_client()
        self.g = Github(self.github_token)
        self.repo_name = self.parse_repo_name(repo)
        self.repo = self.g.get_repo(self.repo_name)
        self.model_name = model 


    def parse_repo_name(self,repo):
        """
        Accepts a GitHub repo URL or 'org/repo' or just 'repo'.
        Returns 'org/repo' if possible, otherwise just 'repo'.
        """
        # Try to extract from URL
        url_match = re.match(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+)", repo)
        if url_match:
            org, repo_name = url_match.group(1), url_match.group(2)
            return f"{org}/{repo_name}"
        # If already in org/repo format
        return repo


    def analyze_with_deepseek(self, code: str, context: str):
        prompt = f"""
You are a code security expert. Analyze the following code snippet and compare it with the suspicious patterns provided.

### CODE TO ANALYZE:
{code}

Compare with the following suspicious patterns:
{context}

### RESPONSE FORMAT:
Return ONLY a JSON object with the following fields:
    "malicious": true/false/"unknown",
    "reason": "short explanation if malicious or unknown",
    "tactic": "tactic or technique used if malicious, or null",
    "needs_more_context": true/false
"""
        # Call external LLM endpoint (e.g., LM Studio running locally)
        url = "http://localhost:1234/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a code security expert."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 512
        }
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"❌ Error calling external LLM: {e}")
            return '{"malicious": "unknown", "reason": "LLM error", "tactic": null, "needs_more_context": true}'

    def run(self):
        results = []
        commits = self.repo.get_commits()
        for commit in commits:
            commit_sha = commit.sha
            print(f"🔍 Analyzing commit {commit_sha}")
            commit_data = self.repo.get_commit(commit_sha)
            for file in commit_data.files:
                try:
                    if hasattr(file, 'patch') and file.patch:
                        added_lines = []
                        for line in file.patch.splitlines():
                            if line.startswith('+++') or line.startswith('---'):
                                continue
                            if line.startswith('+'):
                                added_lines.append(line[1:])
                        decoded = "\n".join(added_lines)
                    else:
                        decoded = ""
                    if not decoded.strip():
                        continue

                    context = ""
                    for collection in self.client.list_collections():
                        similar = collection.query(query_texts=[decoded], n_results=50)
                        if not similar['documents']:
                            continue
                        context += chr(10).join(similar['documents'][0]) if similar['documents'] else '[None found]'
                    print(f"📄 Analyzing {file.filename}...")
                    result_ai = self.analyze_with_deepseek(decoded, context)
                    if result_ai.startswith("```json"):
                        result_ai = result_ai.split("```json")[1].split("```")[0].strip()
                        if result_ai:
                            try:
                                import json
                                result_ai = json.loads(result_ai)
                                if isinstance(result_ai, dict):
                                    if 'malicious' in result_ai and result_ai['malicious']:
                                        results.append({
                                            "commit": commit_sha,
                                            "file": file.filename,
                                            "result": result_ai,
                                            "context": decoded,
                                            "author": commit.author.login if commit.author else "Unknown",
                                            "date": commit.commit.author.date.isoformat()
                                        })
                                        print(f"⚠️ Malicious code detected in {file.filename} at {commit_sha}")
                                    else:
                                        print(f"✅ No malicious code detected in {file.filename} at {commit_sha}")
                            except json.JSONDecodeError as e:
                                print(f"❌ JSON decode error for {file.filename} at {commit_sha}: {e}")
                except Exception as e:
                    print(f"⚠️ Error reading {file.filename} at {commit_sha}: {e}")

        # Print results
        for r in results:
            print("\n==============================")
            print(f"🧾 File: {r['file']}")
            print(f"🔗 Commit: {r['commit']}")
            print(f"🧠 AI Result:\n{r['result']}")

def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Valknut code security analyzer")
    parser.add_argument('--repo', required=False,  help='GitHub repository name (e.g. user/repo)')
    parser.add_argument('--token', required=False, help='GitHub token (or set GITHUB_TOKEN env var)')
    parser.add_argument('--model', required=False, default="deepseek-coder-v2-lite-instruct", help='Model name for analysis')
    args = parser.parse_args()

    github_token = args.token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("❌ GitHub token not provided. Use --token or set GITHUB_TOKEN env var.")
        exit(1)

    analyzer = ValknutAnalyzer(args.repo, github_token, args.model)
    analyzer.run()

if __name__ == "__main__":
    main()