# ProspectScan Security Heatmap

## Arquitectura Frontend B2B - Análisis de Seguridad de Dominios

### Visión General

Heatmap interactivo de seguridad de dominios empresariales construido con React funcional y optimizado para escalabilidad. Implementa arquitectura AUP (Aggregate, Unit, Part) para exploración inteligente de datos.

---

## 🎯 Características Principales

### 1. Vista Global (Aggregate)
- Estadísticas agregadas independientes del dominio individual
- Score promedio de seguridad
- Distribución por niveles (Alta/Media/Baja)
- Distribución por provider (Microsoft 365, Google Workspace, Otro)
- Análisis por subdimensiones (Identity, Exposure, General)

### 2. Exploración Individual (Unit)
- Grid interactivo con todos los dominios
- Selección de dominio para ver detalle contextual
- Navegación sin perder contexto global
- Vista inline (no modal invasivo)

### 3. Búsqueda y Filtrado Inteligente (Part)
- Búsqueda por substring en nombre de dominio
- Filtro por provider
- Ordenamiento por score o nombre
- Resultados en tiempo real con useMemo

---

## 📁 Estructura del Proyecto

```
frontend/
├── src/
│   ├── components/
│   │   ├── DomainHeatmap.jsx       # Componente principal orquestador
│   │   ├── DomainHeatmap.css       # Estilos cohesivos y semánticos
│   │   ├── GlobalSummary.jsx       # Vista agregada independiente
│   │   ├── FilterBar.jsx           # Búsqueda y filtros
│   │   ├── HeatmapGrid.jsx         # Tabla/grid principal
│   │   └── DomainDetail.jsx        # Detalle contextual inline
│   ├── utils/
│   │   ├── domainLogic.js          # Lógica de negocio y scoring
│   │   └── mockData.js             # Datos de ejemplo
│   ├── App.jsx                     # Entry point
│   ├── index.jsx                   # Render principal
│   └── index.css                   # Estilos globales base
├── public/
│   └── index.html                  # HTML base
├── package.json
├── vite.config.js
└── README.md
```

---

## 🎨 Decisiones de Diseño Clave

### 1. Arquitectura AUP (Aggregate-Unit-Part)
**Decisión:** Implementar navegación que permite ver el todo y saltar a cualquier parte sin perder contexto.

**Implementación:**
- `GlobalSummary`: Vista agregada independiente de filtros (muestra siempre el todo)
- `HeatmapGrid`: Lista de unidades (dominios) como entidades principales
- `DomainDetail`: Partes/subdimensiones de cada dominio

**Ventaja:** El usuario siempre sabe dónde está y puede navegar libremente.

---

### 2. Sistema de Colores Semántico Coherente
**Decisión:** Usar verde/amarillo/rojo consistentemente en toda la UI.

**Implementación:**
```javascript
// En domainLogic.js
Verde (#10b981)  → Seguridad Alta / Avanzada
Amarillo (#f59e0b) → Seguridad Media / Intermedia
Rojo (#ef4444)   → Seguridad Baja / Básica
```

**Ventaja:** El usuario aprende rápidamente el código de colores y puede hacer análisis visual sin leer números.

---

### 3. useMemo para Optimización
**Decisión:** Usar React.useMemo para evitar recálculos innecesarios.

**Implementación:**
```javascript
const globalStats = useMemo(() => calculateGlobalStats(domains), [domains]);
const filteredDomains = useMemo(() => filterDomains(...), [deps]);
```

**Ventaja:** Performance óptimo incluso con cientos de dominios. Crítico para escalabilidad.

---

### 4. Componentes Funcionales Puros
**Decisión:** Todos los componentes son funcionales sin estado interno innecesario.

**Implementación:**
- Estado solo en `DomainHeatmap.jsx` (componente orquestador)
- Componentes hijos reciben props y callbacks
- Lógica de negocio separada en `utils/domainLogic.js`

**Ventaja:** Testeable, mantenible, escalable. Permite reutilización fácil.

---

### 5. Vista Inline vs Modal
**Decisión:** Detalle de dominio se muestra inline en panel lateral, no en modal.

**Implementación:**
```jsx
<div className="heatmap-main">
  <HeatmapGrid ... />
  {selectedDomain && <DomainDetail ... />}
</div>
```

**Ventaja:** El usuario no pierde contexto del grid principal. Puede comparar visualmente mientras explora detalle.

---

## 🤖 Puntos de Integración con IA

### 1. Scoring Inteligente (ML)
**Ubicación:** `domainLogic.js → calculateIntelligentScore()`

**Propósito:** Reemplazar scoring basado en reglas con modelo ML que considere:
- Dimensiones de seguridad (identity, exposure, general)
- Provider y sector
- Contexto histórico y tendencias
- Anomalías detectadas

**Integración:**
```javascript
// Actualmente:
export const calculateIntelligentScore = (domain) => domain.score;

// Futuro con ML:
export const calculateIntelligentScore = async (domain) => {
  const features = extractFeatures(domain);
  const prediction = await mlModel.predict(features);
  return prediction.score;
};
```

---

### 2. Insights Automáticos (LLM)
**Ubicación:** `domainLogic.js → generateDomainInsights()`

**Propósito:** Generar insights accionables con LLM:
- "Este dominio tiene configuración SPF débil, recomendar actualización"
- "Proveedor reciente, alto riesgo de phishing"
- "Patrón similar a breaches anteriores"

**Integración:**
```javascript
// Actualmente: reglas hardcoded
export const generateDomainInsights = (domain) => {
  if (domain.score < 40) return ['⚠️ Vulnerabilidad crítica'];
  return [];
};

// Futuro con LLM:
export const generateDomainInsights = async (domain) => {
  const prompt = buildPrompt(domain);
  const insights = await llmAPI.generateInsights(prompt);
  return insights.map(i => ({ text: i, actionable: true }));
};
```

---

### 3. Alertas Predictivas (Anomaly Detection)
**Ubicación:** `domainLogic.js → generatePredictiveAlerts()`

**Propósito:** Detectar patrones anómalos y predecir problemas:
- "3 dominios con score decreciente en última semana"
- "Patrón inusual de cambios de provider"
- "Cluster de dominios de mismo sector con vulnerabilidad común"

**Integración:**
```javascript
// Actualmente: alertas simples
export const generatePredictiveAlerts = (domains) => {
  const lowScore = domains.filter(d => d.score < 30).length;
  return lowScore > 0 ? [{ severity: 'high', message: `${lowScore} críticos` }] : [];
};

// Futuro con Anomaly Detection:
export const generatePredictiveAlerts = async (domains, history) => {
  const timeSeries = buildTimeSeries(domains, history);
  const anomalies = await anomalyModel.detect(timeSeries);
  return anomalies.map(a => formatAlert(a));
};
```

---

### 4. Contactos LinkedIn (Data Enrichment)
**Ubicación:** Futuro componente `ContactsPanel.jsx`

**Propósito:** Integrar contactos de LinkedIn asociados a cada dominio:
- Buscar decisores por dominio
- Mostrar perfil, rol, último activity
- Generar mensajes de prospección personalizados con LLM

**Integración:**
```javascript
// En DomainDetail.jsx - botón "Ver contactos LinkedIn"
const fetchLinkedInContacts = async (domain) => {
  const contacts = await api.getLinkedInContacts(domain);
  return contacts.map(c => enrichWithAI(c)); // LLM genera icebreakers
};
```

---

### 5. Tickets de Prospección Automáticos
**Ubicación:** Futuro módulo `ProspectionTickets.js`

**Propósito:** Generar tickets accionables basados en score y contexto:
- Prioridad automática basada en score y tamaño empresa
- Mensaje personalizado generado por LLM
- Sugerencia de approach (email, LinkedIn, call)

**Integración:**
```javascript
// En DomainDetail.jsx - botón "Generar ticket"
const generateProspectionTicket = async (domain) => {
  const priority = calculatePriority(domain);
  const approach = recommendApproach(domain);
  const message = await llm.generateProspectionMessage(domain);
  
  return {
    domain: domain.domain,
    priority,
    approach,
    message,
    assignee: assignAutomatically(priority)
  };
};
```

---

## 🚀 Próximos Pasos de Escalabilidad

### Backend Integration
1. **API REST para dominios**
   ```javascript
   // En App.jsx
   const [domains, setDomains] = useState([]);
   
   useEffect(() => {
     fetch('/api/domains')
       .then(res => res.json())
       .then(data => setDomains(data));
   }, []);
   ```

2. **Websockets para actualizaciones en tiempo real**
   ```javascript
   const ws = new WebSocket('ws://api.prospectscan.com/updates');
   ws.onmessage = (event) => {
     const update = JSON.parse(event.data);
     updateDomain(update);
   };
   ```

### Estado Global
3. **Context API o Zustand para estado compartido**
   ```javascript
   // ProspectContext.js
   const ProspectContext = createContext();
   
   export const useProspects = () => useContext(ProspectContext);
   ```

### Exportación y Reporting
4. **Exportar análisis en PDF/Excel**
   ```javascript
   // En DomainDetail.jsx
   const exportAnalysis = async (domain) => {
     const report = await api.generateReport(domain);
     downloadFile(report, 'pdf');
   };
   ```

### Autenticación y Multi-tenancy
5. **Usuarios y permisos**
   ```javascript
   // Auth context
   const { user, permissions } = useAuth();
   
   // Mostrar solo dominios permitidos
   const visibleDomains = filterByPermissions(domains, permissions);
   ```

---

## 🛠️ Instalación y Ejecución

### Requisitos
- Node.js >= 18
- npm >= 9

### Setup
```bash
cd frontend
npm install
npm run dev
```

La aplicación se abrirá en `http://localhost:3000`

### Build para producción
```bash
npm run build
```

Los archivos optimizados se generan en `frontend/dist/`

---

## 📊 Performance

### Optimizaciones Implementadas
- ✅ useMemo para stats y filtros
- ✅ Componentes funcionales puros
- ✅ CSS modular y cohesivo
- ✅ Lazy loading preparado (para futuro)
- ✅ Virtualización preparada (para +1000 dominios)

### Benchmarks Esperados
- **20 dominios:** < 50ms render
- **100 dominios:** < 150ms render
- **1000 dominios:** < 500ms con virtualización

---

## 🧪 Testing (Futuro)

### Unit Tests
```bash
npm run test
```

### E2E Tests
```bash
npm run test:e2e
```

---

## 📝 Convenciones de Código

### Componentes
- Nombres en PascalCase: `DomainHeatmap.jsx`
- Props destructuring en parámetros
- PropTypes o TypeScript para validación

### Utilidades
- Nombres en camelCase: `domainLogic.js`
- Funciones puras exportadas
- JSDoc para documentación inline

### Estilos
- CSS Modules o styled-components
- Variables CSS para theming
- Mobile-first responsive

---

## 🤝 Contribución

Este proyecto está diseñado para:
1. **Facilitar onboarding:** Código claro y documentado
2. **Permitir extensiones:** Puntos de integración bien definidos
3. **Escalar sin refactor:** Arquitectura preparada para crecer

---

## 📄 Licencia

Privado - ProspectScan B2B SaaS

---

**Construido con ❤️ y enfoque en UX B2B**
