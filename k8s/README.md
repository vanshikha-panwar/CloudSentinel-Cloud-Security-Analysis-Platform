# CloudSentinel on local Kubernetes (Minikube)

Minimal manifests for running the CloudSentinel REST API on a local cluster:

| File | Resource |
|------|----------|
| `deployment.yaml` | `cloudsentinel` Deployment: 1 replica, non-root (UID 10001), `/health` readiness/liveness probes, SQLite at `/app/data/cloudsentinel.db` |
| `pvc.yaml` | `cloudsentinel-data` PersistentVolumeClaim: 1Gi, `ReadWriteOnce`, default storage class |
| `service.yaml` | `cloudsentinel` NodePort Service on port 8000 |

> **Status:** these manifests have not yet been applied to a cluster (no
> Docker/Kubernetes runtime was available during development).

## Deploy

```bash
minikube start

# Build the image inside Minikube's Docker so the cluster can use it without a registry
eval $(minikube docker-env)          # PowerShell: & minikube -p minikube docker-env --shell powershell | Invoke-Expression
docker build -t cloudsentinel:latest .

kubectl apply -f k8s/
kubectl rollout status deployment/cloudsentinel
kubectl get pods,svc,pvc -l app=cloudsentinel
```

Alternatively, build with your local Docker and run
`minikube image load cloudsentinel:latest`. The Deployment uses
`imagePullPolicy: IfNotPresent`, so it never tries to pull the image from a
registry when it is already present.

## Access

```bash
minikube service cloudsentinel --url     # prints http://<node-ip>:<node-port>
curl <url>/health                        # {"status":"ok"}
```

Interactive API docs are at `<url>/docs`. The API has no authentication, so
keep this on a local cluster only.

## Notes

- **One replica only.** SQLite on a `ReadWriteOnce` volume supports a single
  writer, so the Deployment uses the `Recreate` strategy and must not be scaled up.
- **AI explanations are disabled** (no `CLOUDSENTINEL_LLM_*` variables are set).
  If you enable them, put the API key in a Kubernetes Secret, never in these manifests.
- **Scan history persists** across pod restarts in the `cloudsentinel-data` PVC.
  It contains scanner findings (ARNs, IAM names, access key IDs); treat it as sensitive.

## Remove

```bash
kubectl delete -f k8s/deployment.yaml -f k8s/service.yaml   # keeps the scan history PVC
kubectl delete -f k8s/pvc.yaml                              # deletes the stored history
```
