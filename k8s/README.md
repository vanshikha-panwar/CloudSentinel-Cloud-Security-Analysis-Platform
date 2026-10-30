# CloudSentinel on local Kubernetes

Manifests for running the CloudSentinel REST API on a local cluster
(Minikube, kind or Docker Desktop). No cloud resources are created.

| File | Resource |
|------|----------|
| `configmap.yaml` | `cloudsentinel-config`: non-sensitive settings (`CLOUDSENTINEL_DB_PATH`, AI provider `disabled`, timeout) |
| `deployment.yaml` | `cloudsentinel`: 1 replica, `Recreate` strategy, non-root UID 10001, `/health` readiness/liveness probes, CPU/memory requests and limits, optional Secret reference for the LLM API key |
| `pvc.yaml` | `cloudsentinel-data`: 1Gi `ReadWriteOnce` claim on the default StorageClass, mounted at `/app/data` |
| `service.yaml` | `cloudsentinel`: NodePort Service, port 8000 → container port 8000 |

> **Status:** no cluster was available on the development machine. The CI
> workflow (`.github/workflows/ci.yml`) deploys these manifests to a temporary
> kind cluster and smoke-tests them; the latest Actions run shows the result.

## 1. Make the image available to the cluster

The Deployment uses `cloudsentinel:latest` with `imagePullPolicy: IfNotPresent`,
so the image must already be on the cluster node (it is not in a registry).

```bash
# Minikube: build inside Minikube's Docker
eval $(minikube docker-env)          # PowerShell: & minikube -p minikube docker-env --shell powershell | Invoke-Expression
docker build -t cloudsentinel:latest .

# kind: build locally, then load into the cluster
docker build -t cloudsentinel:latest .
kind load docker-image cloudsentinel:latest

# Docker Desktop Kubernetes: a local `docker build` is visible to the cluster
docker build -t cloudsentinel:latest .
```

## 2. Deploy

```bash
kubectl apply -f k8s/                              # ConfigMap, Deployment, PVC, Service
kubectl rollout status deployment/cloudsentinel
kubectl get pods,svc,pvc,configmap -l app=cloudsentinel
```

## 3. Access, health and logs

```bash
kubectl port-forward service/cloudsentinel 8000:8000     # works on any cluster
curl http://127.0.0.1:8000/health                         # {"status":"ok"}
bash scripts/smoke_test.sh http://127.0.0.1:8000          # full endpoint check

minikube service cloudsentinel --url                      # Minikube: NodePort URL instead of port-forward

kubectl logs -l app=cloudsentinel -f                      # application logs
kubectl describe pod -l app=cloudsentinel                 # probe failures, scheduling and volume events
```

Interactive API docs are at `/docs`. The API has no authentication; keep
it on a local cluster.

## Configuration and secrets

- Non-sensitive settings live in `configmap.yaml`. After changing it:
  `kubectl apply -f k8s/configmap.yaml && kubectl rollout restart deployment/cloudsentinel`.
- The LLM API key is never stored in these files. To enable AI explanations,
  set `CLOUDSENTINEL_LLM_PROVIDER: openai_compatible` plus
  `CLOUDSENTINEL_LLM_BASE_URL` and `CLOUDSENTINEL_LLM_MODEL` in the ConfigMap,
  then create the Secret the Deployment references (optional, so the pod
  starts without it):

  ```bash
  kubectl create secret generic cloudsentinel-llm --from-literal=api-key="<your key>"
  kubectl rollout restart deployment/cloudsentinel
  ```

  Typing the key on the command line stores it in your shell history; use
  `--from-file=api-key=<file>` to avoid that.

## Notes

- **One replica only.** SQLite on a `ReadWriteOnce` volume supports a single
  writer, so the Deployment uses the `Recreate` strategy and must not be scaled up.
- **Scan history persists** across pod restarts in the `cloudsentinel-data` PVC.
  It contains scanner findings (ARNs, IAM names, access key IDs); treat it as sensitive.

## Remove

```bash
kubectl delete -f k8s/configmap.yaml -f k8s/deployment.yaml -f k8s/service.yaml   # keeps the scan history PVC
kubectl delete -f k8s/pvc.yaml                                                     # deletes the stored history
kubectl delete secret cloudsentinel-llm --ignore-not-found
```
