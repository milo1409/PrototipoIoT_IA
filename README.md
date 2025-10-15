# 🧠 ShodanIA — Prototipo de Monitoreo y Análisis de Exposición IoT

**ShodanIA** es un prototipo académico desarrollado como parte de la Maestría en Arquitectura de Software de la Universidad de la Sabana.  
El sistema combina un frontend ligero con un backend en Django para **analizar la exposición pública de dispositivos IoT**, procesar resultados de *scans* de Shodan y visualizar métricas de seguridad.

---

## 🚀 Características principales

- Interfaz web estática (`index.html`) servida por `http.server`.
- Backend Django con endpoints REST para análisis y consultas.
- Integración modular con scripts de análisis basados en Python.
- Estructura de proyecto limpia y portable (venv + requirements).
- Soporte para ejecución local o en contenedores Docker.

---

## 🧩 Estructura del proyecto

```
shodanIA/
├── index.html               # Interfaz principal
├── static/                  # Recursos CSS/JS
├── manage.py                # Gestor Django
├── app/                     # Aplicaciones Django
├── shodanIA/                # Configuración base (settings, urls, wsgi)
├── requirements.txt         # Dependencias del proyecto
└── .venv/                   # Entorno virtual (no se sube a GitHub)
```

---

## ⚙️ Requisitos

- **Python 3.12+**
- **pip** y **virtualenv**
- (Opcional) **Docker** y **Docker Compose**

---

## 🧰 Instalación y configuración

### 1️⃣ Clonar el repositorio
```bash
git clone https://github.com/<tu_usuario>/shodanIA.git
cd shodanIA
```

### 2️⃣ Crear entorno virtual
```bash
python -m venv .venv
.\.venv\Scriptsctivate
```

### 3️⃣ Instalar dependencias
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### 4️⃣ Configurar variables (si aplica)
Crea un archivo `.env` en la raíz:
```env
SHODAN_API_KEY= Key de Shodan https://developer.shodan.io/api 
OPENAI_API_KEY= Key de la Open IA https://openai.com/ 
```

---

## ▶️ Ejecución del prototipo

### 🔹 Frontend (HTML estático)
```bash
python -m http.server 5500
```
Accede en: http://localhost:5500

### 🔹 Backend (Django)
```bash
python manage.py migrate
python manage.py runserver 8000
```
Accede en: http://127.0.0.1:8000

---

## 🐳 (Opcional) Ejecución con Docker

```bash
docker compose up --build
```

Servicios:
- **frontend:** http://localhost:5500  
- **backend:** http://localhost:8000  
- **db (postgres opcional):** localhost:5432

---

## 🧪 Pruebas rápidas

```bash
curl http://127.0.0.1:8000/
```

Verifica que la API responda correctamente.  
El archivo `index.html` puede hacer fetch hacia el backend si defines su URL base en JS:

---

## 🛡️ Notas de desarrollo

- Usa un **entorno virtual** para aislar dependencias.
- No instales paquetes globalmente en Python.
- Excluye de GitHub: `.venv/`, `__pycache__/`, `.env`, `*.db`.
- Para regenerar `requirements.txt`:
  ```bash
  pip freeze > requirements.txt
  ```
---

## 👨‍💻 Autores

**Oscar Clavijo, Yerlinson Maturana, Camilo Porras**  
📍 Proyecto académico — Maestría en Arquitectura de Software Universidad de la Sabana
🕓 2025

---

## 🧠 Licencia

Este prototipo se distribuye bajo licencia **MIT** para fines educativos y de investigación.
