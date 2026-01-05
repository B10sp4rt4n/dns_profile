# ProspectScan - Guía de Setup

## 🚀 Iniciar Sistema Completo

### 1. Backend API (FastAPI)

```bash
cd /workspaces/dns_profile
python api.py
```

- **Puerto:** 8000
- **Health Check:** http://localhost:8000/api/health
- **Documentación:** http://localhost:8000/docs

### 2. Frontend React (Vite)

```bash
cd /workspaces/dns_profile/frontend
npm install  # Solo primera vez
npm run dev
```

- **Puerto:** 5173
- **URL Local:** http://localhost:5173

### 3. Streamlit (Opcional)

```bash
cd /workspaces/dns_profile
streamlit run app_superficie.py
```

- **Puerto:** 8501

---

## 🔧 Configuración para GitHub Codespaces

### Hacer puertos públicos:

```bash
gh codespace ports visibility 8000:public -c $CODESPACE_NAME
gh codespace ports visibility 5173:public -c $CODESPACE_NAME
```

### URLs Públicas (Codespaces):

- **Frontend:** `https://<CODESPACE_NAME>-5173.app.github.dev/`
- **API:** `https://<CODESPACE_NAME>-8000.app.github.dev/`
- **API Docs:** `https://<CODESPACE_NAME>-8000.app.github.dev/docs`

Donde `<CODESPACE_NAME>` es el valor de `$CODESPACE_NAME` (ej: `scaling-dollop-jj7qw7xpr6x7cpwpw`)

---

## 📝 Variables de Entorno

### Frontend (.env)

```env
VITE_API_URL=https://<CODESPACE_NAME>-8000.app.github.dev
```

Para desarrollo local:
```env
VITE_API_URL=http://localhost:8000
```

---

## 🧪 Testing

### Verificar Backend:

```bash
curl http://localhost:8000/api/health
```

### Verificar Dominios:

```bash
curl http://localhost:8000/api/domains | jq length
```

### Analizar Dominio Individual:

```bash
curl -X POST http://localhost:8000/api/analyze/domain \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

---

## 🐛 Troubleshooting

### Frontend muestra "No se pudo conectar con el backend"

1. Verificar que API esté corriendo: `curl http://localhost:8000/api/health`
2. Verificar puerto 8000 sea público: `gh codespace ports`
3. Revisar CORS en `api.py`
4. Verificar VITE_API_URL en `frontend/.env`

### Puerto en uso

```bash
# Liberar puerto 5173
fuser -k 5173/tcp

# Liberar puerto 8000
fuser -k 8000/tcp
```

### Reinstalar dependencias

```bash
# Backend
pip install -r requirements.txt

# Frontend
cd frontend && npm install
```

---

## 📊 Arquitectura

```
┌─────────────────────────────────────────────┐
│          React Frontend (port 5173)         │
│        - DomainHeatmap Component            │
│        - API Service Layer                  │
└─────────────────┬───────────────────────────┘
                  │
                  │ HTTP/REST
                  ▼
┌─────────────────────────────────────────────┐
│         FastAPI Backend (port 8000)         │
│        - /api/domains                       │
│        - /api/analyze/*                     │
│        - /api/stats                         │
└─────────────────┬───────────────────────────┘
                  │
                  │ Imports
                  ▼
┌─────────────────────────────────────────────┐
│       app_superficie.py (Core Logic)        │
│        - analizar_dominio()                 │
│        - analizar_dominios()                │
│        - DNS/HTTP checks                    │
└─────────────────┬───────────────────────────┘
                  │
                  │ PostgreSQL
                  ▼
┌─────────────────────────────────────────────┐
│         Neon Database (Cache)               │
│        - 149 dominios analizados            │
└─────────────────────────────────────────────┘
```

---

## ✅ Checklist de Despliegue

- [ ] API corriendo en puerto 8000
- [ ] Frontend corriendo en puerto 5173
- [ ] Puertos públicos configurados
- [ ] VITE_API_URL correcta en frontend/.env
- [ ] Backend retorna datos: `/api/domains`
- [ ] Frontend muestra Heatmap con datos reales
- [ ] CORS configurado correctamente
- [ ] Tests básicos pasando
