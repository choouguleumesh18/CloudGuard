import sys
import types
from cloudguard.services.job_dispatcher import KubernetesJobDispatcher


def test_dispatcher_creates_scan_job(monkeypatch):
    from cloudguard.core.config import settings
    monkeypatch.setattr(settings,"kubernetes_namespace","cloudguard-test")
    monkeypatch.setattr(settings,"worker_image","example.azurecr.io/cloudguard:test")
    captured={}
    class Batch:
        def create_namespaced_job(self, namespace, body): captured.update(namespace=namespace,body=body)
    client=types.ModuleType("kubernetes.client"); client.BatchV1Api=Batch
    config=types.ModuleType("kubernetes.config"); config.load_incluster_config=lambda:None; config.load_kube_config=lambda:None
    config.ConfigException=type("ConfigException",(Exception,),{})
    kubernetes=types.ModuleType("kubernetes"); kubernetes.__path__=[]; kubernetes.client=client; kubernetes.config=config
    monkeypatch.setitem(sys.modules,"kubernetes",kubernetes)
    monkeypatch.setitem(sys.modules,"kubernetes.client",client)
    monkeypatch.setitem(sys.modules,"kubernetes.config",config)
    dispatcher=KubernetesJobDispatcher()
    job_name=dispatcher.dispatch_scan("scan-123","sub-12345678","test-user")
    assert captured["namespace"]=="cloudguard-test"
    assert captured["body"]["metadata"]["name"]==job_name
    assert captured["body"]["spec"]["template"]["spec"]["containers"][0]["args"]==["scan","--scan-id","scan-123","--subscription-id","sub-12345678","--actor","test-user"]
