# Container Security Analyzer

Analizador estatico de seguridad para archivos de configuracion de contenedores. Detecta malas practicas en `Dockerfile`, `docker-compose.yml`, manifiestos Kubernetes y archivos `.env`.

La aplicacion no ejecuta contenedores. El analisis es estatico.

## Funcionalidades

- Analisis web con carga multiple de archivos.
- Motor modular por tipo de archivo.
- Deteccion de secretos con redaccion automatica antes de responder, guardar o exportar.
- Historial local en `history.json`, sin base de datos.
- Exportacion de reportes en HTML, JSON y SARIF.
- CLI para escanear archivos, carpetas o repositorios completos.
- Scoring de seguridad de 0 a 100 con grado A-F y explicacion de penalizacion.
- Referencias a controles como CIS Docker, Kubernetes Pod Security Standards, OWASP Secrets Management y NSA/CISA Kubernetes.
- Token API opcional para despliegues productivos.

## Instalacion

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
flask run
```

En Linux/macOS:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask run
```

Abre `http://127.0.0.1:5000`.

## Configuracion

Variables relevantes:

```env
SECRET_KEY=change-this-in-production-immediately
APP_AUTH_TOKEN=
MAX_CONTENT_LENGTH=16777216
HISTORY_MAX_SIZE=50
HISTORY_FILE=history.json
STORE_FULL_HISTORY=true
```

Si `APP_AUTH_TOKEN` tiene valor, las rutas `/api/*` requieren `X-API-Token: <token>` o `Authorization: Bearer <token>`. El frontend incluye un campo para guardar ese token en `localStorage`.

`STORE_FULL_HISTORY=true` guarda hallazgos completos pero sanitizados. Si lo cambias a `false`, el historial conserva solo resumen y metadatos.

## Uso CLI

Escanear el repositorio actual:

```bash
python scan.py .
```

Generar JSON:

```bash
python scan.py . --format json --output report.json
```

Generar SARIF para CI:

```bash
python scan.py . --format sarif --output results.sarif
```

Fallar el pipeline si hay hallazgos altos o criticos:

```bash
python scan.py . --fail-on high
```

## Pruebas

```bash
python -m pytest
```

## Reglas principales

- Privilegios: `USER root`, `privileged:true`, `hostPID`, `hostNetwork`, `allowPrivilegeEscalation`, capacidades peligrosas.
- Red: puertos peligrosos, `network_mode: host`, servicios Kubernetes `NodePort` o `LoadBalancer`.
- Secretos: valores sensibles en `.env`, `ENV`, `ARG`, `RUN`, `environment` y ConfigMaps.
- Supply chain: imagenes sin tag fijo, `latest`, `curl | bash`, upgrades no reproducibles.
- Hardening: `read_only`, `no-new-privileges`, `cap_drop: ALL`, `seccompProfile`, token de ServiceAccount automontado.
- Recursos: limites de memoria y CPU ausentes.

## Despliegue en Azure App Service

El workflow incluido despliega a un App Service existente usando publish profile.

1. Crea el App Service Linux con Python 3.12.
2. Descarga el publish profile desde Azure Portal.
3. Agrega el secreto `AZURE_WEBAPP_PUBLISH_PROFILE` en GitHub Actions.
4. Configura en Azure las variables `SECRET_KEY`, `FLASK_ENV=production` y, opcionalmente, `APP_AUTH_TOKEN`.
5. Haz push a `main` o ejecuta el workflow manualmente.
