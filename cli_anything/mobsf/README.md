# cli-anything-mobsf

CLI-Anything harness for MobSF. See [MOBSF.md](../../MOBSF.md) for full usage.

## Quick start

```bash
pip install -e ../../agent-harness
export MOBSF_URL=http://localhost:8000
cli-anything-mobsf upload app.apk
cli-anything-mobsf scan
cli-anything-mobsf report --json
```
