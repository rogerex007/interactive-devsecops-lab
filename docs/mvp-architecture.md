# DevSecOps Interactive Lab - MVP Architecture Blueprint

## 1. Product Vision
El laboratorio DevSecOps sirve como un hub interactivo para planificar, ejecutar y visualizar módulos de seguridad integrados en el ciclo de desarrollo. Los usuarios principales incluyen equipos DevOps/SRE, ingenieros de seguridad, desarrolladores y el personal instructor encargado de formar Security Champions.

## 2. MVP Feature Set
### 2.1 Panel y orquestación
- Panel central que indique el estado de los servicios base del laboratorio (health-check up/down).
- Lanzamiento y programación de tareas de seguridad: Semgrep, Trivy, OWASP ZAP, entre otros.
- Ejecución y monitoreo de pipelines CI/CD de ejemplo, con controles de start/stop y visualización de logs.

### 2.2 Resultados y reportes
- Visualización unificada de resultados SAST/SCA/DAST/IaC con métricas de severidad.
- Detalle de CVEs, enlaces a documentación oficial (OWASP, Semgrep, MobSF) y descargas en CSV/PDF.
- Almacenamiento de reportes y artefactos en MinIO para acceso histórico.

### 2.3 Entornos y ejercicios
- Despliegue y teardown de entornos por módulo mediante Docker Compose o clusters k3d.
- Repositorios de aplicaciones vulnerables (OWASP Juice Shop, dvna, APIs de muestra).
- Playbooks y ejercicios guiados con validaciones automáticas para Security Champions.

### 2.4 Gestión y analítica
- Administración de usuarios y roles (Instructor / Student) con autenticación JWT o Keycloak.
- Registro de actividades y métricas (MTTR simulado, porcentaje de builds bloqueados).

## 3. Arquitectura Lógica
```
┌──────────────────────────┐        ┌──────────────────────────┐
│        Frontend SPA      │        │      Backend API         │
│  React + Vite + Tailwind │◀──────▶│  Node.js (Express/Nest)  │
└────────────┬─────────────┘        └────────────┬─────────────┘
             │                                   │
             ▼                                   ▼
      ┌───────────────┐                   ┌───────────────┐
      │  Auth (JWT/   │                   │   Orchestrador│
      │  Keycloak)    │                   │   (scripts,    │
      └───────────────┘                   │   Docker/k3d)  │
             │                           ┌┴───────────────┴┐
             ▼                           │                 │
   ┌─────────────────┐             ┌─────▼─────┐   ┌───────▼──────┐
   │  PostgreSQL     │             │  MinIO    │   │ Sistemas Lab │
   │  (metadata)     │             │(artefactos│   │  (SAST/DAST/ │
   └─────────────────┘             │  reportes)│   │   SCA/IaC)   │
                                   └──────────┘   └──────────────┘
```

## 4. Componentes Principales
### 4.1 Frontend
- SPA React (Vite) con Tailwind y React Router.
- Páginas clave: Dashboard, Laboratorios, Ejecutar Escaneo, Resultados, Usuarios, Playbooks.
- Notificaciones en tiempo real vía WebSockets o SSE para actualizaciones de tareas.

### 4.2 Backend API
- Node.js con Express o NestJS para estructura más modular.
- Endpoints para orquestar contenedores, disparar scanners, gestionar usuarios y exponer resultados.
- Integración con colas de trabajos (BullMQ/Redis) para ejecutar tareas largas sin bloquear.

### 4.3 Orquestación Local
- Docker Compose como base para servicios (SonarQube, Nexus, MobSF, ZAP, Prometheus, Grafana, MinIO).
- Clusters k3d para simular Kubernetes local, con soporte para políticas (Gatekeeper/OPA).
- Scripts Bash/Python invocados por el backend para levantar/monitorizar scans y pipelines.

### 4.4 Persistencia y Artefactos
- PostgreSQL para metadatos, configuraciones de labs y gestión de usuarios/roles.
- MinIO como almacenamiento de resultados (.json, .html, .pdf) y evidencia de ejercicios.
- File shares montados en contenedores para compartir reportes entre servicios.

### 4.5 Servicios de Laboratorio
- Integración con herramientas: SonarQube y Semgrep (SAST), Trivy/Grype (SCA & container), Checkov/tfsec (IaC), OWASP ZAP (DAST), MobSF (mobile).
- Nexus OSS o registry local para gestión de imágenes y paquetes.
- Repositorios de aplicaciones vulnerables listos para ejercicios prácticos.

### 4.6 CI/CD de Demostración
- Pipelines ejemplo mediante GitHub Actions (runner local) o Jenkins en contenedor.
- Ejecución desde el panel con logs y estados expuestos en tiempo real.

### 4.7 Observabilidad y Seguridad
- Prometheus + Grafana para métricas, con posibilidad de extender a stack ELK para logs.
- Aislamiento por laboratorio con redes Docker dedicadas, recursos limitados via cgroups y namespaces.
- Opcional: despliegue del laboratorio en VM o WSL2 para aislar del host principal.

## 5. Flujo de Caso de Uso: Escaneo SCA + DAST
1. El instructor crea un laboratorio “Pipeline Seguro” desde la UI.
2. El backend provisiona la app vulnerable mediante `docker-compose up` y registra un job en la cola.
3. El usuario ejecuta “SCA” desde la interfaz; el backend dispara Trivy/Semgrep, almacena los resultados en MinIO y guarda metadatos en PostgreSQL.
4. Se notifica al usuario en la UI y se listan vulnerabilidades y CVEs relevantes.
5. El usuario ejecuta “DAST”; el backend levanta OWASP ZAP para spider/scan y almacena el reporte generado.
6. El tablero muestra el resumen de severidades y enlaces de remediación (OWASP cheat-sheets).
7. El instructor asigna ejercicios; los checks automatizados validan la corrección de vulnerabilidades específicas.

## 6. Consideraciones de Próximos Pasos
- Sustituir scripts simulados por ejecución real en contenedores dedicados y registros de resultados en la base de datos.
- Implementar autenticación JWT/Keycloak con separación de roles y permisos granulados.
- Añadir programación de tareas recurrentes y pipelines personalizados.
- Integrar dashboards de observabilidad (Grafana) con alertas basadas en métricas clave (MTTR simulado, builds bloqueados).
- Diseñar exportaciones en PDF/CSV y conectores a documentación oficial.
- Expandir soporte para despliegues Kubernetes con políticas OPA/Gatekeeper y monitoreo continuo.
