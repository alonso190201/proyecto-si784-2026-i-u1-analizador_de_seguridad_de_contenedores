# Container Security Analyzer 🛡️

Una herramienta profesional y modular de análisis estático desarrollada con Python Flask para detectar vulnerabilidades, configuraciones inseguras y anti-patrones de seguridad en archivos de configuración de contenedores.

> **Importante:** Esta aplicación realiza únicamente *análisis estático*. No ejecuta contenedores ni realiza pruebas activas de penetración.

---

## Características

- **Soporte Multi-Formato:** Analiza archivos `Dockerfile`, `docker-compose.yml`, manifiestos de Kubernetes (`.yaml`) y archivos `.env`.
- **Motor de Reglas:** Analizadores modulares con reglas específicas para detección de secretos, escalación de privilegios, exposición de red y riesgos de cadena de suministro.
- **Dashboard Moderno:** Interfaz oscura con temática de ciberseguridad, efectos glassmorphism, carga mediante arrastrar y soltar y gráficos animados.
- **Sistema de Puntuación:** Calcula un puntaje de seguridad (0-100) y asigna una calificación (A-F) basada en la severidad de los hallazgos.
- **Reportes:** Exportación de reportes HTML detallados y autocontenidos.
- **Privacidad:** Historial únicamente en memoria (no requiere base de datos).

---

## Arquitectura

- **Backend:** Python 3.12, Flask, Werkzeug
- **Frontend:** HTML5, Bootstrap 5, Vanilla JS, Chart.js, FontAwesome
- **Despliegue:** Preparado para Azure App Service Linux (incluye `Procfile`, `startup.sh` y workflow de GitHub Actions).

---

## Instalación

1. **Clonar el repositorio** (o descargar los archivos).

2. **Crear un entorno virtual:**

```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. **Instalar dependencias:**

```bash
pip install -r requirements.txt
```

4. **Variables de entorno:**

Renombra `.env.example` a `.env` y configura tus ajustes.

---

## Uso

Ejecutar la aplicación localmente:

```bash
flask run
```

O usando Gunicorn:

```bash
gunicorn app:app --bind=0.0.0.0:8000
```

Luego navega a:

```text
http://127.0.0.1:5000
```

(o puerto 8000) desde tu navegador.

Arrastra y suelta tus archivos de configuración en el área de carga y haz clic en **"Start Analysis"**.

---

## Categorías de Reglas

### Escalación de Privilegios

Detecta:
- `privileged: true`
- `USER root`
- `hostPID`
- entre otros.

### Seguridad de Red

Detecta:
- `hostNetwork`
- puertos peligrosos expuestos (`22`, `2375`, `3389`).

### Gestión de Secretos

Detección basada en expresiones regulares para:
- claves API hardcodeadas
- tokens
- contraseñas

en:
- `ENV`
- `ARG`
- archivos `.env`
- ConfigMaps.

### Cadena de Suministro

Detecta:
- etiquetas de imágenes sin fijar (`latest`)
- imágenes base no oficiales
- ejecución insegura de scripts remotos (`curl | bash`).

### Restricciones de Recursos

Marca:
- ausencia de límites de memoria
- ausencia de límites de CPU.

---

## Despliegue en Azure App Service

Este repositorio incluye un workflow de GitHub Actions:

```text
.github/workflows/azure-deploy.yml
```

### Pasos

1. Crear una Web App en Azure App Service:
   - Linux
   - Python 3.12

2. Descargar el **Publish Profile** desde el portal de Azure.

3. En tu repositorio de GitHub ir a:

```text
Settings > Secrets and variables > Actions
```

4. Agregar un secreto llamado:

```text
AZURE_WEBAPP_PUBLISH_PROFILE
```

y pegar el contenido XML del publish profile.

5. Hacer push a la rama `main` para activar el despliegue automático.
