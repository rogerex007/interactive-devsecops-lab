
# DevSecOps Lab - MVP Scaffold

Este repositorio contiene un scaffold mínimo para un laboratorio DevSecOps organizacional.

## Cómo usar (local)
1. Asegúrate de tener Docker y Docker Compose instalados.

2. En la raíz del repo ejecuta:

```bash
docker-compose up --build
```

3. Servicios:
- Frontend: http://localhost:3000
- Backend API: http://localhost:4000/api
- Juice Shop (app vulnerable): http://localhost:3001


## Endpoints importantes
- `GET /api/health` - estado básico

- `GET /api/labs` - lista de labs disponibles

- `POST /api/labs/:id/run` - iniciar job. Body: { "job": "semgrep" | "trivy" | "zap" }

- `GET /api/results/:file` - obtener resultados (archivo JSON)


## Estructura
{
  'backend': 'API Express, resultados en backend/results',
  'frontend': 'Vite + React minimal dashboard',
  'scripts': 'simulaciones de scanners (semgrep, trivy, zap)',
}

## Próximos pasos
- Reemplazar scripts simulados por llamadas reales a semgrep/trivy/zap dentro de contenedores
- Añadir autenticación y roles
- Integrar MinIO para almacenamiento real de reportes
- Añadir k3d para despliegues Kubernetes y OPA
