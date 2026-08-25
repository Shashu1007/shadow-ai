# DPDP Drift Scanner — production image
#
# Two things run out of this same image, selected by CMD/entrypoint arg at
# `fly.toml` / `railway.json` level:
#   1. The Flask dashboard (always-on web process)
#   2. run_scan.py (one-shot, invoked by a scheduled job — see fly.toml)
#
# Base image: Playwright's official Python image ships Chromium + every apt
# dependency it needs already installed and version-matched to the `playwright`
# pip package. Building this from `python:3.11-slim` yourself means manually
# apt-installing ~15 shared libraries (libnss3, libatk-bridge, libgbm, etc.) —
# not worth it for an MVP. Pin the tag to match the playwright version in
# requirements.txt; check https://playwright.dev/python/docs/docker for the
# current tag if you bump that version.
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

# Install Python deps first (separate layer -> cached across code-only rebuilds)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Playwright's base image already has Chromium installed at this path (their
# own Dockerfile sets this same var, so this line is normally redundant) —
# asserted explicitly here as a defensive default so app/agents/crawler.py's
# sync_playwright().chromium.launch() reliably finds it even if a future base
# image tag changes that default. This project never runs `playwright
# install` in the image — that's a separate command from `pip install
# playwright` (which does NOT download a browser on its own) and would be
# redundant with what the base image already ships.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PYTHONUNBUFFERED=1

# SQLite lives on a mounted volume in production so it survives redeploys —
# see fly.toml's [mounts] section. Directory must exist before the volume
# mounts over it on first boot.
RUN mkdir -p /app/data /app/logs

# Run as a non-root user. The Playwright base image's Chromium is already
# installed system-wide and readable by any user, so this doesn't need a
# `playwright install` re-run — just ownership of /app so the app user can
# write to data/ and logs/ (the volume mount inherits root ownership by
# default on first create; chown again after mounting if a fresh volume
# ever shows up owned by root — `fly ssh console -C "chown -R appuser
# /app/data"` — the image-build chown below only covers the image layer).
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Platform-level health check (also referenced from fly.toml/railway.json):
# hits /healthz, which is intentionally unauthenticated (see app/auth.py)
# and checks the DB is actually reachable, not just that the process is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).status == 200 else 1)"

# Default command runs the dashboard behind gunicorn (a real WSGI server —
# Flask's own dev server is single-threaded and not meant to face the
# internet). The scheduled scan job overrides this at the platform level
# (fly.toml [[processes]] / a Railway cron trigger / the GitHub Actions
# workflow) to run `python run_scan.py --all` instead — same image,
# different entrypoint, no separate build.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app.web:app"]
