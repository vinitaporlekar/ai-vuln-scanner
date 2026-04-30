import httpx
import re

GITHUB_API = "https://api.github.com"
SCANNABLE = {".py", ".js", ".ts", ".java", ".cpp", ".c", ".html", ".css", ".rb", ".go", ".rs", ".php"}

def parse_github_url(url):
    url = url.strip().rstrip("/")
    match = re.match(r"(?:https?://)?github\.com/([^/]+)/([^/]+)", url)
    if not match:
        return None
    return {"owner": match.group(1), "repo": match.group(2).replace(".git", "")}

async def fetch_repo_files(owner, repo):
    async with httpx.AsyncClient() as client:
        repo_res = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}")
        if repo_res.status_code != 200:
            return {"error": f"Repo not found: {owner}/{repo}", "status": repo_res.status_code}
        branch = repo_res.json().get("default_branch", "main")
        tree_res = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
        if tree_res.status_code != 200:
            return {"error": "Could not fetch file tree", "status": tree_res.status_code}
        files = []
        for item in tree_res.json().get("tree", []):
            if item["type"] != "blob":
                continue
            ext = "." + item["path"].rsplit(".", 1)[-1] if "." in item["path"] else ""
            if ext.lower() in SCANNABLE:
                files.append({"path": item["path"], "size": item.get("size", 0)})
        return {"owner": owner, "repo": repo, "branch": branch, "total_files": len(tree_res.json().get("tree", [])), "scannable_files": len(files), "files": files}

async def fetch_file_content(owner, repo, file_path):
    async with httpx.AsyncClient() as client:
        res = await client.get(f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{file_path}")
        return res.text if res.status_code == 200 else None