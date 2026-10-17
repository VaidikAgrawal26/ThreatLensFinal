# Render deployment guide

This repository contains a Render Blueprint at `render.yaml` for a demonstration deployment with three services: a Docker-based FastAPI web service, a static Vite frontend, and Render Postgres. It does not create any Render resources by itself; connect the repository in Render and review the Blueprint before creating services.

## Before creating the Blueprint

1. Push this repository to a Git provider connected to your Render account.
2. In Render, create a Blueprint from that repository and select the project root containing `render.yaml`.
3. Review the service names and plan. The Blueprint uses Render's free plans for a low-cost demonstration. Free web services can spin down while idle; free Postgres is temporary and expires after 30 days. Use an appropriate paid database plan if scan history must persist beyond that period. Render filesystems are ephemeral, so user-managed YARA rule changes do not survive a restart/redeploy; bundled demo rules do.
4. The Blueprint prompts for `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`. Enter the admin account you intend to use. Render generates `JWT_SECRET` for the service.
5. The default CORS origin is `https://threatlens-demo-ui.onrender.com`. If Render assigns the frontend a different hostname, update the API service's `CORS_ORIGINS` to that exact frontend origin and redeploy the API.

## After the services are created

1. Wait for the API health check at `/ready` to pass. The API migrates the database schema during startup.
2. Sign in to the frontend with the bootstrap admin account.
3. After the admin account has been created successfully, remove `BOOTSTRAP_ADMIN_PASSWORD` (and optionally the email) from the API environment and redeploy. The service bootstraps only if that email is absent from the database.
4. In the app, inspect model readiness. The backend pins scikit-learn 1.9.1, the version used to serialize the selected Random Forest. If readiness reports a version mismatch or unavailable artifact, do not interpret that as a benign prediction.
5. Use only inert, valid PE demonstration fixtures that you are authorized to upload. The scanner reads uploaded bytes and does not execute them. The model supports `.exe` PE samples; a non-PE file renamed to `.exe` is rejected.
6. Clearly describe the model output as a partial static estimate. It imputes unavailable runtime telemetry, so a selected demo fixture demonstrates the application path, not detection accuracy or ground truth.

## What persists

Scan metadata, extracted analysis results, and accounts are stored in PostgreSQL. Submitted file bytes are discarded after analysis. Do not expect uploaded samples to be downloadable later. The YARA rules included in the container are present after each deploy, but rule files uploaded through the UI are written to the service filesystem and can disappear after restart/redeploy because this Blueprint does not attach a persistent disk.

The API binds to Render's `PORT`, runs one worker to limit memory use for the model, and selects the pinned candidate artifact and paired schema. The frontend receives the API's generated public URL from the Blueprint; API CORS is restricted to the configured frontend origin.

## Manual dashboard fallback

If you create services manually instead of using the Blueprint:

- API: Docker runtime, Dockerfile `backend/Dockerfile`, build context `backend`, health check `/ready`.
- Frontend: static site, root directory `frontend`, build command `npm ci && npm run build`, publish directory `dist`.
- Database: Render Postgres; connect `DATABASE_URL` to its internal connection string.
- API environment: set `ENVIRONMENT=production`, `PORT=10000`, `WEB_CONCURRENCY=1`, a generated `JWT_SECRET`, exact `CORS_ORIGINS` and `TRUSTED_HOSTS`, bootstrap admin credentials, and the candidate model/schema paths shown in `render.yaml`.
- Frontend environment: set `VITE_API_URL` to the API's public HTTPS URL and rebuild after changing it.

Keep the API and database in the same Render region so the API can use the private database URL.
