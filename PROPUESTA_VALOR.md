# ProspectScan - Propuesta de Valor

## 🎯 ¿Qué es ProspectScan?

**ProspectScan** es una plataforma de inteligencia comercial que analiza la superficie digital de empresas para identificar oportunidades de venta en servicios de ciberseguridad y TI.

A diferencia de herramientas genéricas de prospección, ProspectScan **detecta vulnerabilidades reales** que se convierten en argumentos de venta personalizados y urgentes.

---

## 💡 Problema que Resuelve

### El desafío del vendedor de ciberseguridad:

| Método tradicional | Problema |
|-------------------|----------|
| Llamadas en frío | Tasa de conversión < 2% |
| Emails genéricos | "No nos interesa" |
| Demos sin contexto | Sin urgencia de compra |
| LinkedIn masivo | Percibido como spam |

### La realidad:
- El 76% de los compradores B2B prefieren vendedores que entienden su negocio
- El 91% de los ciberataques comienzan con un email (phishing)
- Solo el 27% de las empresas tienen DMARC en modo "reject"
- El 64% de los sitios web no tienen protección WAF/CDN

**ProspectScan convierte estos datos en oportunidades de venta.**

---

## 🔍 ¿Qué Analiza?

### 1. Seguridad de Correo (Identidad Digital)

| Control | Qué detecta | Oportunidad de venta |
|---------|-------------|---------------------|
| **SPF** | Configuración de remitentes autorizados | Email Security, Anti-spoofing |
| **DMARC** | Política de autenticación de correo | Servicios DMARC, Monitoreo |
| **MX Records** | Proveedor de correo actual | Migración, Gateway de seguridad |

### 2. Exposición Web

| Control | Qué detecta | Oportunidad de venta |
|---------|-------------|---------------------|
| **HTTPS** | Certificado SSL/TLS | Certificados, hardening |
| **HSTS** | Forzado de conexión segura | Consultoría web |
| **CSP** | Políticas de contenido | Desarrollo seguro |
| **WAF/CDN** | Protección perimetral | Cloudflare, Imperva, etc. |

### 3. Infraestructura

| Control | Qué detecta | Oportunidad de venta |
|---------|-------------|---------------------|
| **Servidor** | Tecnología web (Nginx, Apache, IIS) | Hardening, migración |
| **Tecnología** | Framework (PHP, .NET, Node.js) | Desarrollo seguro |
| **Antigüedad** | Años del dominio | Contexto de madurez |

---

## 📊 Métricas de la Plataforma

### Score de Oportunidad (0-100)
- **0-30**: 🔴 Crítico - Alta probabilidad de cierre
- **31-50**: 🟠 Oportunidad clara - Buen prospecto
- **51-70**: 🟡 Intermedio - Requiere educación
- **71-100**: 🟢 Maduro - Menor urgencia

### Clasificación de Postura
- **Básica**: Sin controles fundamentales → Venta consultiva
- **Intermedia**: Controles parciales → Upselling
- **Avanzada**: Bien protegido → Partnership/referidos

---

## 💰 ROI Esperado

### Escenario: 1,000 dominios analizados

| Etapa | Cantidad | Tasa |
|-------|----------|------|
| Dominios analizados | 1,000 | 100% |
| Con oportunidades (score < 50) | 350-400 | 35-40% |
| Contactos efectivos | 100-150 | 10-15% |
| Reuniones agendadas | 25-40 | 2.5-4% |
| Propuestas enviadas | 15-25 | 1.5-2.5% |
| **Cierres** | **5-10** | **0.5-1%** |

### Comparativa con prospección tradicional:

| Método | Reuniones/1000 contactos | Cierres/1000 |
|--------|-------------------------|--------------|
| Llamada fría | 10-20 | 1-2 |
| Email genérico | 5-10 | 0.5-1 |
| **ProspectScan** | **25-40** | **5-10** |

### Valor por cierre (servicios de ciberseguridad):
- Implementación DMARC: $2,000 - $10,000 USD
- Email Security Gateway: $5,000 - $50,000 USD/año
- WAF/CDN Enterprise: $10,000 - $100,000 USD/año
- Consultoría de seguridad: $5,000 - $25,000 USD

**ROI potencial con 5 cierres mínimos: $25,000 - $250,000 USD**

---

## 🎯 Casos de Uso

### 1. Partner de Microsoft 365
```
Análisis: Empresas con MX apuntando a servidores propios
Pitch: "Detectamos que aún usan servidor de correo on-premise. 
       ¿Han evaluado migrar a Microsoft 365 con protección ATP?"
```

### 2. Vendedor de Email Security
```
Análisis: Empresas con DMARC en p=none o sin DMARC
Pitch: "Su dominio puede ser suplantado en ataques de phishing.
       El 91% de los ransomware empiezan así. ¿15 minutos para mostrarlo?"
```

### 3. Proveedor de WAF/CDN
```
Análisis: Empresas sin Cloudflare/Imperva detectado
Pitch: "Su sitio web está expuesto directamente a internet sin 
       protección DDoS. Podemos demostrarlo en 5 minutos."
```

### 4. Consultor de Cumplimiento
```
Análisis: Empresas con múltiples controles ausentes
Pitch: "Analizamos su superficie digital y encontramos gaps 
       que podrían afectar su cumplimiento de PCI-DSS/ISO 27001."
```

---

## 📧 Templates de Outreach

### Email #1: Apertura con valor

**Asunto:** Análisis de seguridad de [DOMINIO] - hallazgos importantes

```
Hola [NOMBRE],

Realicé un análisis de la superficie digital de [EMPRESA] y encontré 
algunas áreas de oportunidad que quiero compartirte:

🔴 DMARC: No está en modo "reject" - su dominio puede ser suplantado
🟡 WAF: No detectamos protección perimetral en su sitio web
🟡 HSTS: Las conexiones no fuerzan HTTPS

Esto no es un pitch de venta, es información que creo les será útil.

¿Tienes 15 minutos esta semana para mostrarte el análisis completo?

Saludos,
[TU NOMBRE]
```

### Email #2: Follow-up con urgencia

**Asunto:** Re: [EMPRESA] - dato adicional

```
Hola [NOMBRE],

Quería agregarte un dato: el 91% de los ataques de ransomware 
comienzan con un email de phishing.

Sin DMARC en modo "reject", cualquiera puede enviar emails 
haciéndose pasar por [EMPRESA].

Solo toma 15 minutos mostrarte cómo se ve esto y qué opciones tienen.

¿Jueves o viernes funcionan?

[TU NOMBRE]
```

### LinkedIn InMail

```
Hola [NOMBRE], vi que eres [CARGO] en [EMPRESA].

Hice un análisis rápido de su dominio y encontré que no tienen 
DMARC configurado en modo enforce. Esto significa que cualquiera 
podría enviar emails suplantando su identidad.

No busco venderte nada, solo compartir el hallazgo.

¿Te interesa que te envíe el reporte?
```

---

## 🏆 Ventajas Competitivas

### vs. ZoomInfo ($15,000+/año)
- ✅ Enfocado en seguridad, no solo contactos
- ✅ Datos técnicos reales, no estimaciones
- ✅ Costo accesible

### vs. BuiltWith ($295-995/mes)
- ✅ Incluye análisis de seguridad de correo
- ✅ Score de oportunidad comercial
- ✅ Recomendaciones de pitch

### vs. Herramientas gratuitas (MXToolbox, etc.)
- ✅ Análisis masivo automatizado
- ✅ Consolidación de múltiples fuentes
- ✅ Interfaz visual y exportable

---

## 🚀 Funcionalidades

### Actuales
- [x] Análisis masivo desde CSV de emails
- [x] Detección de SPF, DMARC, MX
- [x] Análisis de headers HTTP de seguridad
- [x] Detección de CDN/WAF
- [x] Score de oportunidad 0-100
- [x] Clasificación de postura (Básica/Intermedia/Avanzada)
- [x] Cache inteligente (7 días)
- [x] Exportación a CSV
- [x] Análisis de dominio único

### Roadmap
- [ ] Templates de email personalizados por hallazgo
- [ ] Integración con CRM (HubSpot, Salesforce)
- [ ] API para automatización
- [ ] Alertas de cambios en dominios monitoreados
- [ ] Análisis de subdominios
- [ ] Detección de tecnologías web (WordPress, Shopify, etc.)
- [ ] Score de probabilidad de cierre con ML

---

## 📈 Métricas de Éxito

### Para el usuario de ProspectScan:
1. **Tasa de apertura de emails** > 40% (vs 15-25% genérico)
2. **Tasa de respuesta** > 10% (vs 1-3% genérico)
3. **Reuniones/100 contactos** > 5 (vs 1-2 genérico)
4. **Tiempo de ciclo de venta** -30% (urgencia basada en datos)

### Para la empresa prospectada:
1. Visibilidad de su postura de seguridad
2. Recomendaciones accionables
3. Benchmark vs industria

---

## 💼 Modelo de Negocio (Sugerido)

### SaaS B2B

| Plan | Precio | Incluye |
|------|--------|---------|
| **Starter** | $49/mes | 500 análisis/mes, 1 usuario |
| **Professional** | $149/mes | 2,000 análisis/mes, 5 usuarios, API |
| **Enterprise** | $499/mes | Ilimitado, white-label, integraciones |

### Servicios adicionales:
- Capacitación en uso comercial: $500 USD
- Integración con CRM: $1,000 USD
- Reportes personalizados: $200/reporte

---

## 📞 Contacto

**ProspectScan** - Inteligencia Comercial para Ciberseguridad

Desarrollado con ❤️ para equipos de ventas de seguridad.

---

*Última actualización: Enero 2026*
