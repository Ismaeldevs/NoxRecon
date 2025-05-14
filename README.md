# 🕵️‍♂️ NoxRecon - OSINT Toolkit

**NoxRecon** es una herramienta de código abierto orientada al **OSINT (Open Source Intelligence)** y al reconocimiento de infraestructura digital, diseñada para equipos de **Red Teaming**, pentesters y profesionales de ciberseguridad ofensiva.

> “El conocimiento es poder. El reconocimiento es el primer paso.”

---

## 🚀 Características principales

- 🔎 WHOIS Lookup  
- 🌐 DNS Lookup (A, MX, NS)  
- 🔁 Reverse IP Lookup  
- 🔍 Subdominios con [crt.sh](https://crt.sh)  
- 🧠 Detección de tecnologías web con WhatWeb  
- 🗺️ Geolocalización de IPs  
- 🗂️ Extracción de metadatos de archivos (ExifTool)

Todo en una interfaz estética e intuitiva que te sumerge en una experiencia profesional de análisis.

---

## 🖥️ Compatibilidad

NoxRecon ha sido probado en los siguientes sistemas operativos:

- ✅ Kali Linux (recomendado)
- ✅ Parrot OS
- ✅ Ubuntu / Debian-based
- ✅ Arch Linux
- ⚠️ Windows WSL (limitado, requiere dependencias manuales)

---

## ⚙️ Instalación

1. Clona el repositorio:
```bash
git clone https://github.com/tuusuario/noxrecon.git
cd noxrecon
```
2. Instalación de Dependencias
```sudo apt update && sudo apt install -y whois dig curl jq whatweb exiftool```

3. Instalación de la herramienta
```pip install .```

4. Ejecuta NoxRecon
```noxrecon --help```

![NoxRecon Screenshot](https://private-user-images.githubusercontent.com/32105395/443435749-25468676-c2f1-40d9-af85-d0048a83ee9d.png)

---

## 🧪 Requisitos técnicos
- Python 3.8 o superior (Recomendado: 3.10+)
- Acceso Red y terminal UNIX-like
- Herramientas de CLI: `dig`, `whois`, `curl`, `jq`, `whatweb`, `exiftool`

---

## ⚠️ Responsabilidad y uso ético

> NoxRecon fue creado con fines educativos y de evaluación profesional.

- ❗ No está diseñada para actividades ilegales o sin autorización previa.
- ❗ El uso indebido de esta herramienta es responsabilidad exclusiva del usuario.
- ✅ Úsala únicamente en entornos controlados, con permiso explícitos o fines de aprendizaje.

---

## 🥷 Autor

[@Ismaeldevs](https://www.ismaeldev.com/)

---

## 📜 Licencia
Este proyecto está licenciado bajo la licencia MIT – consulta el archivo [LICENSE](https://github.com/Ismaeldevs/NoxRecon/blob/main/LICENSE) para más detalles.

---

## ⭐ ¿Te resulto útil o te gusto la herramienta?
> ¡Deja una estrella ⭐ al repositorio y contribuye para seguir mejorando la herramienta!
