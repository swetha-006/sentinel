# Controlled payments target

This app is a deliberately small, controlled demo environment, not production payment software. It stores state in memory and must never process real payments or real customer data. `requirements.txt` pins vulnerable third-party versions to exercise GitLab Dependency Scanning. The Docker image uses Python 3.8 to accommodate the intentionally old PyYAML pin; this is a lab-only compatibility choice, not a recommended runtime baseline.

See [`CVE-MANIFEST.md`](CVE-MANIFEST.md) for the six publicly documented CVE mappings, affected-version references and applicability notes. A dependency finding is not the same as a proven remotely exploitable route. The app intentionally does not expose every vulnerable code path.

## Run locally

Use a disposable virtual environment, install the pinned requirements, then run:

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8080
```

The API is in-memory and resets on restart. Do not expose it to the public internet or deploy it to production.
