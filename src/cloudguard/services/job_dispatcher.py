from uuid import uuid4
from cloudguard.core.config import settings

class KubernetesJobDispatcher:
    """Dispatch short-lived scan/remediation workers as Kubernetes Jobs."""
    def __init__(self):
        from kubernetes import client, config
        try: config.load_incluster_config()
        except config.ConfigException: config.load_kube_config()
        self.client=client
        self.batch=client.BatchV1Api()

    def _create(self, task: str, args: list[str]):
        name=f"cloudguard-{task}-{uuid4().hex[:12]}"
        body={
            "apiVersion":"batch/v1", "kind":"Job",
            "metadata":{"name":name,"namespace":settings.kubernetes_namespace,"labels":{"app":"cloudguard","task":task}},
            "spec":{"backoffLimit":settings.retry_limit,"ttlSecondsAfterFinished":86400,"template":{
                "metadata":{"labels":{"app":"cloudguard-worker","azure.workload.identity/use":"true"}},
                "spec":{"restartPolicy":"Never","serviceAccountName":"cloudguard-automation","securityContext":{"runAsNonRoot":True,"runAsUser":10001},
                    "containers":[{"name":"worker","image":settings.worker_image,"command":["python","-m","cloudguard.worker"],"args":args,"envFrom":[{"secretRef":{"name":"cloudguard-config"}}],"resources":{"requests":{"cpu":"100m","memory":"256Mi"},"limits":{"cpu":"1000m","memory":"768Mi"}}}]}}}}
        self.batch.create_namespaced_job(namespace=settings.kubernetes_namespace,body=body)
        return name

    def dispatch_scan(self, scan_id: str, subscription_id: str, actor: str):
        return self._create("scan",["scan","--scan-id",scan_id,"--subscription-id",subscription_id,"--actor",actor])

    def dispatch_remediation(self, request_id: str):
        return self._create("remediate",["remediate","--request-id",request_id])
