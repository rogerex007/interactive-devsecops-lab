# 🛡️ DevSecOps Lab - Interactive Security Dashboard

Un laboratorio interactivo de DevSecOps con dashboard profesional, herramientas de seguridad y generación automática de workflows de CI/CD.

## 🚀 Características Principales

### 📊 Dashboard Interactivo
- **Métricas en tiempo real** de vulnerabilidades y escaneos
- **Gráficos interactivos** con Chart.js (severidad, herramientas, tipos de vulnerabilidades)
- **Tabla de CVEs** con enlaces directos y información de remediación
- **Modal de reportes** con visualización detallada de hallazgos
- **Diseño profesional** estilo Vulnerability Manager Plus

### 🔧 Herramientas de Seguridad Reales
- **🔍 Semgrep** - Static Application Security Testing (SAST)
- **📦 Trivy** - Software Composition Analysis (SCA)
- **🌐 OWASP ZAP** - Dynamic Application Security Testing (DAST)

### 🚀 Generador de Workflows CI/CD
- **GitHub Actions** - Workflows YAML completos
- **Azure DevOps Pipelines** - Pipelines YAML enterprise
- **Configuración visual** de herramientas y notificaciones
- **Templates predefinidos** para casos comunes
- **Preview en tiempo real** del código generado

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │  Security Tools │
│   React + Vite  │◄──►│   Express API   │◄──►│  Semgrep/Trivy  │
│   Chart.js      │    │   Docker Exec   │    │  OWASP ZAP      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Dashboard UI   │    │  PostgreSQL     │    │  MinIO Storage  │
│  Workflow Mgmt  │    │  Database       │    │  Reports        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Inicio Rápido

### Prerrequisitos
- Docker y Docker Compose
- Node.js 20+ (para desarrollo local)

### Instalación

1. **Clonar el repositorio:**
```bash
git clone git@github.com:rogerex007/interactive-devsecops-lab.git
cd interactive-devsecops-lab
```

2. **Ejecutar con Docker Compose:**
```bash
docker-compose up --build
```

3. **Acceder a los servicios:**
- 🎯 **Dashboard Principal:** http://localhost:3000
- 🔧 **API Backend:** http://localhost:4000/api
- 🍊 **Juice Shop (App Vulnerable):** http://localhost:3001
- 📦 **MinIO Storage:** http://localhost:9001

## 📋 Uso del Dashboard

### 🔍 Ejecutar Escaneos de Seguridad

1. **Accede al dashboard** en http://localhost:3000
2. **Haz clic en los botones** de herramientas de seguridad:
   - 🔍 **SAST** (Semgrep) - Análisis estático de código
   - 📦 **SCA** (Trivy) - Análisis de dependencias
   - 🌐 **DAST** (ZAP) - Análisis dinámico de aplicaciones

3. **Visualiza los resultados** en tiempo real en las métricas y gráficos

### 📄 Ver Reportes Detallados

1. **Haz clic en "📄 Ver Reporte"** en la sección "Resultados Detallados"
2. **Explora el modal interactivo** con:
   - Métricas de vulnerabilidades
   - Gráfico de torta de severidad
   - Lista detallada de hallazgos
   - Información de CVEs con enlaces
   - Guías de remediación

### 🚀 Generar Workflows CI/CD

1. **Haz clic en "🚀 Workflows"** en el header
2. **Configura tu pipeline:**
   - Selecciona plataforma (GitHub Actions o Azure DevOps)
   - Elige herramientas de seguridad
   - Configura triggers y notificaciones
3. **Copia el código generado** y pégalo en tu repositorio

## 🔌 API Endpoints

### Información General
- `GET /api/health` - Estado de servicios
- `GET /api/labs` - Lista de laboratorios disponibles

### Ejecución de Escaneos
- `POST /api/labs/:id/run` - Ejecutar escaneo
  ```json
  {
    "job": "semgrep" | "trivy" | "zap"
  }
  ```

### Resultados
- `GET /api/results` - Lista de resultados
- `GET /api/results/:file` - Obtener resultado específico

### Workflows
- `GET /api/workflows/templates` - Templates predefinidos
- `POST /api/workflows/generate` - Generar workflow personalizado

## 🛠️ Desarrollo

### Estructura del Proyecto

```
├── backend/                 # API Express + Herramientas de seguridad
│   ├── index.js            # Servidor principal
│   ├── test-app.js         # App con vulnerabilidades para testing
│   └── results/            # Reportes generados
├── frontend/               # Dashboard React + Vite
│   ├── src/
│   │   ├── components/
│   │   │   ├── SecurityDashboard.jsx    # Dashboard principal
│   │   │   └── WorkflowManager.jsx      # Generador de workflows
│   │   └── main.jsx
│   └── package.json
├── docker-compose.yml      # Orquestación de servicios
└── README.md
```

### Desarrollo Local

1. **Backend:**
```bash
cd backend
npm install
npm start
```

2. **Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Agregar Nuevas Herramientas

1. **Agregar servicio en `docker-compose.yml`**
2. **Implementar endpoint en `backend/index.js`**
3. **Actualizar frontend para mostrar la nueva herramienta**

## 🔒 Seguridad

### Vulnerabilidades de Ejemplo
El proyecto incluye `backend/test-app.js` con vulnerabilidades intencionales:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Weak Authentication
- Command Injection
- Information Disclosure

### Configuración de Seguridad
- Contenedores ejecutan herramientas en modo aislado
- Resultados almacenados en volúmenes Docker seguros
- API con validación de entrada

## 📊 Herramientas Integradas

| Herramienta | Tipo | Descripción |
|-------------|------|-------------|
| **Semgrep** | SAST | Análisis estático de código fuente |
| **Trivy** | SCA | Escaneo de vulnerabilidades en dependencias |
| **OWASP ZAP** | DAST | Análisis dinámico de aplicaciones web |

## 🎯 Casos de Uso

### Para Desarrolladores
- Ejecutar escaneos de seguridad en código local
- Generar workflows CI/CD para proyectos
- Aprender sobre vulnerabilidades comunes

### Para Equipos DevOps
- Integrar seguridad en pipelines existentes
- Monitorear métricas de seguridad
- Automatizar reportes de seguridad

### Para Equipos de Seguridad
- Evaluar herramientas de seguridad
- Crear templates de seguridad para la organización
- Capacitar equipos de desarrollo

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.