# 🕵️‍♂️ NoxRecon v2.0.0 - Professional OSINT Toolkit

[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)](https://github.com/Ismaeldevs/NoxRecon)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

**NoxRecon** es un toolkit profesional de recolección de información (OSINT) diseñado por y para pentesters y profesionales de ciberseguridad. Combina múltiples técnicas de obtención de datos en una interfaz moderna, intuitiva y multiplataforma.

> *"El conocimiento es poder. El reconocimiento es el primer paso hacia la seguridad."*

---

## ✨ Características Principales v2.0.0

### 🔍 **Operaciones OSINT**
- 🔎 **WHOIS Lookup** - Información de registro de dominios e IPs
- 🌐 **DNS Lookup** - Consulta completa de registros DNS (A, AAAA, MX, NS, TXT, CNAME, SOA)
- 🔄 **Reverse IP Lookup** - Resolución inversa de IPs a hostnames
- 🎯 **Subdomain Enumeration** - Búsqueda de subdominios via Certificate Transparency
- 🧠 **Web Technology Detection** - Análisis de tecnologías web y frameworks
- 🗺️ **IP Geolocation** - Localización geográfica con múltiples fuentes
- 🗂️ **Metadata Extraction** - Extracción de metadatos de archivos

### 🎨 **Interfaz Profesional**
- ✨ Interfaz interactiva con **questionary** y **Rich**
- 📊 Tablas formateadas y barras de progreso
- 🎭 Sistema de estilos profesionales
- 🌈 Soporte completo de colores y emojis

### 🪟 **Compatibilidad Multiplataforma**
- ✅ **Windows** (con fallbacks Python nativos)
- ✅ **Linux** (herramientas nativas + fallbacks)
- ✅ **macOS** (herramientas Unix + fallbacks)
- 🔧 Detección automática de dependencias

### ⚙️ **Características Avanzadas**
- 🔒 Sistema de validación de entrada robusto
- 🛡️ Manejo de errores comprensivo
- ⚡ Operaciones asíncronas para mejor rendimiento
- 📝 Sistema de configuración personalizable
- 🎯 Rate limiting inteligente

---

## 🚀 Instalación Rápida

### Windows (Recomendado)
```batch
# 1. Clonar el repositorio
git clone https://github.com/Ismaeldevs/NoxRecon.git
cd NoxRecon

# 2. Ejecutar installer automático
install_windows.bat

# 3. Ejecutar NoxRecon
noxrecon.bat
```

### Linux/macOS
```bash
# 1. Clonar el repositorio
git clone https://github.com/Ismaeldevs/NoxRecon.git
cd NoxRecon

# 2. Instalar dependencias del sistema (Ubuntu/Debian)
sudo apt update && sudo apt install -y whois dnsutils curl jq whatweb exiftool

# 3. Instalar NoxRecon
pip install -e .

# 4. Ejecutar
noxrecon
```

### Instalación Manual (Cualquier Sistema)
```bash
# 1. Crear entorno virtual
python -m venv noxrecon_env
source noxrecon_env/bin/activate  # Windows: noxrecon_env\Scripts\activate

# 2. Instalar dependencias Python
pip install -r requirements.txt

# 3. Instalar en modo desarrollo
pip install -e .

# 4. Ejecutar
python -m noxrecon.menu
```

---

## 🎯 Uso Rápido

### Menú Interactivo
```bash
noxrecon
```

### Línea de Comandos
```bash
# WHOIS lookup
noxrecon whois example.com

# DNS lookup
noxrecon dns example.com

# Subdomain enumeration
noxrecon subdomains example.com

# IP geolocation
noxrecon geo 8.8.8.8
```

---

## 📋 Dependencias

### Python (Requeridas)
- **Python 3.8+**
- requests >= 2.31.0
- rich >= 13.7.0
- questionary == 2.0.1
- dnspython >= 2.4.0
- aiohttp >= 3.9.0
- colorama == 0.4.6
- validators >= 0.22.0

### Herramientas Externas (Opcionales)
- **whois** - Consultas WHOIS nativas
- **dig** - Consultas DNS avanzadas
- **curl** - Requests HTTP
- **whatweb** - Detección de tecnologías web
- **exiftool** - Extracción de metadatos

> ⚠️ **Nota**: En Windows, todas las funcionalidades tienen fallbacks Python nativos.

---

## 🖥️ Compatibilidad

| Sistema Operativo | Soporte | Herramientas Nativas | Fallbacks Python |
|------------------|---------|---------------------|------------------|
| 🪟 Windows 10/11 | ✅ Completo | Limitadas | ✅ Completos |
| 🐧 Linux (Ubuntu/Debian) | ✅ Completo | ✅ Completas | ✅ Disponibles |
| 🐧 Linux (Arch/CentOS) | ✅ Completo | ✅ Completas | ✅ Disponibles |
| 🍎 macOS | ✅ Completo | ⚠️ Parciales | ✅ Completos |
| 🔧 WSL (Windows) | ✅ Completo | ✅ Completas | ✅ Disponibles |

---

## 🎨 Screenshots

### Menú Principal
```
███╗░░██╗░█████╗░██╗░░██╗██████╗░███████╗░█████╗░░█████╗░███╗░░██╗
████╗░██║██╔══██╗╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗░██║
██╔██╗██║██║░░██║░╚███╔╝░██████╔╝█████╗░░██║░░╚═╝██║░░██║██╔██╗██║
██║╚████║██║░░██║░██╔██╗░██╔══██╗██╔══╝░░██║░░██╗██║░░██║██║╚████║
██║░╚███║╚█████╔╝██╔╝╚██╗██║░░██║███████╗╚█████╔╝╚█████╔╝██║░╚███║
╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚══╝

🕵️‍♂️ Advanced OSINT Reconnaissance Toolkit
by Pentesters, for Pentesters
Version 2.0.0 | Enhanced Edition
```

### Resultados DNS
```
┌── DNS Records for example.com (7 types found) ──┐
│ A (IPv4 Address)     │ 93.184.216.34        │
│ MX (Mail Exchange)   │ 10 mail.example.com  │
│ NS (Name Servers)    │ ns1.example.com      │
│ TXT (Text Records)   │ v=spf1 include:...   │
└─────────────────────────────────────────────────┘
```

---

## 🔧 Configuración Avanzada

NoxRecon v2.0.0 incluye un sistema de configuración flexible:

```python
# ~/.noxrecon/config.json
{
  "general": {
    "timeout": 30,
    "user_agent": "NoxRecon/2.0.0",
    "output_format": "table"
  },
  "dns": {
    "nameservers": ["8.8.8.8", "1.1.1.1"],
    "record_types": ["A", "AAAA", "MX", "NS", "TXT"]
  },
  "ui": {
    "style": "professional",
    "animations": true,
    "progress_bars": true
  }
}
```

---

## 🛡️ Características de Seguridad

- ✅ **Validación de entrada** robusta
- ✅ **Rate limiting** inteligente  
- ✅ **Timeout handling** configurable
- ✅ **Error handling** comprensivo
- ✅ **Input sanitization** automática
- ✅ **No persistent storage** de targets por defecto

---

## 🔄 Changelog v2.0.0

### ✨ Nuevas Características
- 🎨 Interfaz completamente rediseñada con Rich y questionary
- 🪟 Soporte completo para Windows con fallbacks Python
- 📊 Sistema de tablas y progress bars profesionales
- ⚙️ Framework de configuración y validación
- 🔄 Operaciones asíncronas para mejor rendimiento
- 🌐 Múltiples fuentes de geolocalización
- 🎯 Detección automática de dependencias

### 🔧 Mejoras
- ✅ DNS lookup con dnspython (7 tipos de registro)
- ✅ Subdomain enumeration con live checking
- ✅ WHOIS lookup con múltiples fallbacks
- ✅ Web tech detection mejorada
- ✅ Metadata extraction con validaciones
- ✅ Error handling robusto

### 🪟 Soporte Windows
- ✅ Installer batch automático
- ✅ Fallbacks Python para todas las operaciones
- ✅ Detección de PowerShell y herramientas nativas
- ✅ Configuración automática de entorno virtual

---

## 👥 Contribuir

¡Las contribuciones son bienvenidas! Por favor:

1. Fork el repositorio
2. Crea una branch para tu feature (`git checkout -b feature/amazing-feature`)
3. Commit tus cambios (`git commit -m 'Add amazing feature'`)
4. Push a la branch (`git push origin feature/amazing-feature`)
5. Abre un Pull Request

---

## ⚠️ Responsabilidad y Uso Ético

> **NoxRecon fue creado con fines educativos y de evaluación profesional autorizada.**

### ✅ Uso Permitido
- 🎓 Educación y aprendizaje
- 🔒 Pentesting autorizado
- 🛡️ Red Team exercises
- 🧪 Laboratorios de práctica
- 🏢 Evaluaciones de seguridad corporativa

### ❌ Uso Prohibido
- 🚫 Actividades ilegales
- 🚫 Reconocimiento no autorizado
- 🚫 Violación de términos de servicio
- 🚫 Acceso no autorizado a sistemas

**El uso indebido de esta herramienta es responsabilidad exclusiva del usuario.**

---

## 👨‍💻 Autor

**NoxRecon Team**
- GitHub: [@Ismaeldevs](https://github.com/Ismaeldevs)
- Website: [ismaeldev.com](https://www.ismaeldev.com/)
- Twitter: [@Ismaeldevs](https://twitter.com/Ismaeldevs)

---

## 📜 Licencia

Este proyecto está licenciado bajo la **Licencia MIT** - consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- 🎨 [Rich](https://github.com/Textualize/rich) - Terminal formatting
- ❓ [Questionary](https://github.com/tmbo/questionary) - Interactive prompts  
- 🌐 [dnspython](https://github.com/rthalley/dnspython) - DNS toolkit
- 🔗 [requests](https://github.com/psf/requests) - HTTP library
- 📊 [crt.sh](https://crt.sh) - Certificate Transparency logs

---

## ⭐ ¿Te gustó NoxRecon?

Si encontraste útil esta herramienta:
- ⭐ **Deja una estrella** en el repositorio
- 🍴 **Fork** el proyecto para contribuir
- 📢 **Comparte** con la comunidad de ciberseguridad
- 🐛 **Reporta bugs** para mejorar la herramienta

---

<div align="center">


*Hecho con ❤️ para la comunidad de ciberseguridad*

</div>
