# CENTINELA - Ecosystem Integration

## Overview
Centinela es el sistema de seguridad central del ecosistema de agentes IA de Daniel Gonzalez.
Cualquier agente que procese prompts de usuarios debe enviarlo a Centinela antes de ejecutarlo.

## SDK disponible
Ubicacion: C:\Users\admin\Desktop\pluma\lib\centinela.ts
Funcion principal: sendPromptToCentinela(params: CentinelaEvent)

## Flujo de integracion
1. Agente recibe prompt del usuario
2. Agente llama sendPromptToCentinela() con el prompt
3. Centinela analiza y devuelve resultado
4. Si blocked=true, agente NO ejecuta el prompt
5. Si blocked=false, agente procede normalmente

## Respuesta del SDK
{
  blocked: boolean,
  risk_score: number,
  action: ALLOW | RESTRICT | BLOCK,
  incident_id?: string,
  threat_types?: string[]
}

## Endpoint directo
POST https://centinela-backend-kzwk.onrender.com/api/v1/prompt/analyze
Body: { content, agent, user, model }

## Agentes del ecosistema
- PLUMA: agente editorial - integrado con SDK
- CEREBRO: agente estrategico - pendiente integracion
- MCF: agente financiero - pendiente integracion
- BUSCADOR: agente de tendencias - pendiente integracion
- SNIFF_AMAZON: agente comercial - pendiente integracion
- LABORATORIO: agente marketing - pendiente integracion
- CREADOR_APIS: agente dev - pendiente integracion

## Autenticacion
- Login: POST /api/v1/auth/login con username/password
- Token JWT valido por 25 minutos
- El SDK maneja el token automaticamente con cache

## Limites
- Payload maximo: 10000 chars
- Rate limit login: 5/minute
- Cold start Render: hasta 50 segundos
