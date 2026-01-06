# 📊 Análisis Estructural Automatizado

Sistema de generación de reportes narrativos basados exclusivamente en datos observables del análisis de superficie digital.

## 🎯 Objetivo

Generar análisis estructurados y audit-friendly que:
- ✅ No inventan datos
- ✅ Son compatibles con OpenAI/ChatGPT para post-procesamiento
- ✅ Funcionan en modo batch, API o Streamlit
- ✅ Son legalmente defendibles

## 📁 Archivos

### `analisis_estructural.py`
Módulo principal con las funciones de generación de análisis:

```python
from analisis_estructural import (
    generar_analisis_estructural,  # Genera análisis de una fila
    procesar_csv,                  # Procesa CSV completo
    procesar_dataframe,            # Procesa DataFrame existente
    exportar_markdown,             # Exporta a .md
    exportar_txt                   # Exporta a .txt
)
```

### `ejemplo_analisis_estructural.py`
Script de ejemplo para uso desde línea de comandos:

```bash
python ejemplo_analisis_estructural.py prospectscan_cruce_20260106.csv
```

Genera automáticamente:
- `analisis_estructural_batch.txt`
- `analisis_estructural_batch.md`
- `analisis_estructural_batch.csv`

## 🚀 Uso

### 1. Desde línea de comandos

```bash
# Procesar CSV
python analisis_estructural.py archivo.csv salida.csv

# Usar script de ejemplo completo
python ejemplo_analisis_estructural.py archivo.csv
```

### 2. Desde Python

```python
import pandas as pd
from analisis_estructural import procesar_dataframe, exportar_txt

# Cargar datos
df = pd.read_csv("prospectscan_cruce_20260106.csv")

# Generar análisis
resultados = procesar_dataframe(df)

# Exportar
exportar_txt(resultados, "analisis_batch.txt")

# Ver análisis individual
print(resultados[0]['analisis'])
```

### 3. Desde Streamlit (integrado)

En la aplicación Streamlit ([app_superficie.py](app_superficie.py)):

1. Ve al tab **"Pipeline Cruce"**
2. Carga tu Excel de ZoomInfo
3. Procesa los dominios
4. Haz clic en **"📝 Generar Análisis Estructural"**
5. Descarga en formato TXT o Markdown

## 📋 Estructura del Análisis

Cada análisis incluye 7 secciones:

```
1. IDENTIFICACIÓN DE LA ORGANIZACIÓN
   - Empresa, dominio, país, empleados, industria, ingresos

2. POSTURA DECLARADA DEL ENTORNO DIGITAL
   - Postura de identidad, exposición y general

3. SUPERFICIE DE CORREO ELECTRÓNICO
   - Proveedor, gateway, SPF, DMARC, mecanismos de envío

4. SUPERFICIE WEB
   - HTTPS, CDN/WAF, HSTS, CSP

5. SCORE Y PRIORIDAD
   - Score de seguridad, prioridad, score de oportunidad

6. NARRATIVA EXISTENTE
   - Factores positivos, negativos, talking points

7. INFORMACIÓN ECONÓMICA
   - Budget estimado (min/max)

CONCLUSIÓN
   - Resumen ejecutivo basado en datos observables
```

## 🤖 Integración con OpenAI/ChatGPT

El análisis generado puede ser enviado a modelos de lenguaje para:

### Post-procesamiento
```python
import openai

analisis_original = resultados[0]['analisis']

# Reformular para C-Level
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[
        {
            "role": "system",
            "content": "Eres un analista de ciberseguridad. "
                      "Resume análisis técnicos para comités ejecutivos."
        },
        {
            "role": "user",
            "content": f"Resume este análisis para C-Level:\n\n{analisis_original}"
        }
    ]
)

print(response.choices[0].message.content)
```

### Casos de uso
- **Reformulación por audiencia**: C-Level, técnico, comercial
- **Resumen ejecutivo**: Extraer solo lo crítico
- **Auditoría de consistencia**: Verificar coherencia del análisis
- **Generación de recomendaciones**: Sugerencias accionables

## 🔧 Configuración

No requiere configuración adicional. Usa las mismas columnas del DataFrame de ProspectScan:

```python
# Columnas requeridas (usa las que existan)
COLUMNAS = [
    'empresa', 'dominio', 'pais', 'empleados', 'industria', 'revenue',
    'postura_identidad', 'postura_exposicion', 'postura_general',
    'correo_proveedor', 'correo_gateway', 'correo_envio',
    'spf_estado', 'dmarc_estado',
    'https_estado', 'cdn_waf', 'hsts', 'csp',
    'score', 'prioridad', 'prioridad_num', 'score_oportunidad',
    'factores_positivos', 'factores_negativos', 'talking_points',
    'budget_min', 'budget_max', 'dominio_antiguedad'
]
```

## 📤 Formatos de exportación

| Formato | Descripción | Uso recomendado |
|---------|-------------|------------------|
| **TXT** | Texto plano con formato | Revisión rápida, email |
| **Markdown** | Formato Markdown con sintaxis | Documentación, GitHub |
| **CSV** | Datos estructurados | Análisis masivo, Excel |

## ✅ Características

### Audit-friendly
- No inventa datos
- Solo usa información observable
- Valores faltantes se marcan como "No disponible"
- Trazabilidad completa

### Batch-ready
- Procesa múltiples dominios en paralelo
- Exportación masiva en múltiples formatos
- Compatible con scripts de automatización

### Copilot-compatible
- Código limpio y documentado
- Funciones modulares y reutilizables
- Sin dependencias externas complejas

### AUP-compatible
- Análisis basado en datos públicos observables
- Sin inferencias no autorizadas
- Diseño defensible legalmente

## 🔄 Flujo de trabajo recomendado

```
1. Cargar CSV/Excel
   └──> procesar_csv() o procesar_dataframe()

2. Generar análisis
   └──> resultados = [{empresa, dominio, analisis}, ...]

3. Exportar según necesidad
   ├──> exportar_txt() - Para revisión
   ├──> exportar_markdown() - Para documentación
   └──> DataFrame.to_csv() - Para análisis

4. (Opcional) Post-procesar con OpenAI
   └──> Reformular, resumir, auditar
```

## 🎓 Ejemplos avanzados

### Filtrar por prioridad antes de exportar
```python
df = pd.read_csv("prospectscan_cruce_20260106.csv")

# Solo críticos y altos
df_filtrado = df[df['prioridad'].isin(['🔴 Crítica', '🟠 Alta'])]

# Generar análisis solo de críticos
resultados = procesar_dataframe(df_filtrado)
exportar_txt(resultados, "analisis_criticos.txt")
```

### Integración con pipeline de CI/CD
```bash
#!/bin/bash
# pipeline.sh

# 1. Generar análisis
python analisis_estructural.py input.csv output.csv

# 2. Subir a storage
aws s3 cp analisis_batch.txt s3://bucket/reportes/

# 3. Notificar
curl -X POST webhook_url -d "Análisis completado"
```

### API REST simple
```python
from fastapi import FastAPI, UploadFile
from analisis_estructural import procesar_csv
import pandas as pd

app = FastAPI()

@app.post("/analizar")
async def analizar_csv(file: UploadFile):
    df = pd.read_csv(file.file)
    resultados = procesar_dataframe(df)
    return {"resultados": resultados}
```

## 📚 Recursos adicionales

- [app_superficie.py](app_superficie.py) - Integración Streamlit
- [db_cache.py](db_cache.py) - Cache de dominios
- [README.md](README.md) - Documentación general

## 🤝 Contribuciones

Este módulo está diseñado para ser:
- **Extensible**: Fácil agregar nuevas secciones al análisis
- **Mantenible**: Código limpio y documentado
- **Auditable**: Sin magic numbers ni lógica oculta

Para agregar nuevas secciones al análisis, edita `generar_analisis_estructural()` en [analisis_estructural.py](analisis_estructural.py).

## 📧 Soporte

Para dudas o reportar problemas, revisa:
1. El código en `analisis_estructural.py` (está bien documentado)
2. El script de ejemplo `ejemplo_analisis_estructural.py`
3. La integración en Streamlit (tab "Pipeline Cruce")
