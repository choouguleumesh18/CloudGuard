import argparse
from cloudguard.db.session import SessionLocal
from cloudguard.services.scan_service import run_scan
from cloudguard.services.worker_service import run_remediation_job

def main():
    parser=argparse.ArgumentParser(prog="cloudguard-worker"); sub=parser.add_subparsers(dest="command",required=True)
    scan=sub.add_parser("scan"); scan.add_argument("--scan-id",required=True); scan.add_argument("--subscription-id",required=True); scan.add_argument("--actor",default="automation-service")
    remediate=sub.add_parser("remediate"); remediate.add_argument("--request-id",required=True)
    args=parser.parse_args(); db=SessionLocal()
    try:
        if args.command=="scan":
            result=run_scan(db,args.subscription_id,args.actor,scan_id=args.scan_id); db.commit()
            if result.status=="failed": raise SystemExit(1)
        else:
            result=run_remediation_job(db,args.request_id)
            if result.status=="failed": raise SystemExit(1)
    finally: db.close()
if __name__=="__main__": main()
