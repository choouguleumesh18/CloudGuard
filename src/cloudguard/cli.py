import argparse
import json
import os
import urllib.request

def _post(url: str, body: dict, token: str | None = None):
    headers={"Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(url,data=json.dumps(body).encode(),headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=300) as response: return json.loads(response.read().decode())

def main():
    parser=argparse.ArgumentParser(prog="cloudguard"); sub=parser.add_subparsers(dest="command",required=True)
    scan=sub.add_parser("scan"); scan.add_argument("--subscription-id",required=True); scan.add_argument("--base-url",default=os.getenv("CLOUDGUARD_URL","http://127.0.0.1:8000")); scan.add_argument("--token",default=os.getenv("CLOUDGUARD_TOKEN"))
    args=parser.parse_args()
    if args.command=="scan":
        base=args.base_url.rstrip("/"); token=args.token
        if not token:
            username=os.getenv("CLOUDGUARD_USERNAME"); password=os.getenv("CLOUDGUARD_PASSWORD")
            if not username or not password: parser.error("Set CLOUDGUARD_TOKEN or CLOUDGUARD_USERNAME and CLOUDGUARD_PASSWORD")
            token=_post(base+"/api/v1/auth/login",{"username":username,"password":password})["access_token"]
        result=_post(base+"/api/v1/scans",{"subscription_id":args.subscription_id},token)
        print(json.dumps(result,indent=2))
if __name__=="__main__": main()
