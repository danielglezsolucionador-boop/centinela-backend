const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://centinela-backend-kzwk.onrender.com';

export const api = {
  async health() {
    const res = await fetch(`${API_URL}/api/v1/health`);
    return res.json();
  },
  async analyzePrompt(payload: {
    prompt: string;
    agent: string;
    user: string;
    model?: string;
  }) {
    const res = await fetch(`${API_URL}/api/v1/prompt/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  },
  async getEcosystemRisk() {
    const res = await fetch(`${API_URL}/api/v1/risk/ecosystem`);
    return res.json();
  },
  async getThreatMemory() {
    const res = await fetch(`${API_URL}/api/v1/threat-memory`);
    return res.json();
  },
  async getIncidents() {
    const res = await fetch(`${API_URL}/api/v1/incidents`);
    return res.json();
  },
  async getCorrelations() {
    const res = await fetch(`${API_URL}/api/v1/correlations/active`);
    return res.json();
  },
  async getObservabilityMetrics() {
    const res = await fetch(`${API_URL}/api/v1/observability/metrics`);
    return res.json();
  },
  async getAgentsMap() {
    const res = await fetch(`${API_URL}/api/v1/agents/map`);
    return res.json();
  },
  async getResponseStats() {
    const res = await fetch(`${API_URL}/api/v1/response/stats`);
    return res.json();
  },
  async getPolicies() {
    const res = await fetch(`${API_URL}/api/v1/policies`);
    return res.json();
  },
  async getForensics() {
    const res = await fetch(`${API_URL}/api/v1/forensics`);
    return res.json();
  },
  async getThreatIntelligence() {
    const res = await fetch(`${API_URL}/api/v1/threat-intelligence`);
    return res.json();
  },
};

export function createWebSocket(onMessage: (data: unknown) => void) {
  const wsUrl = API_URL.replace('https://', 'wss://').replace('http://', 'ws://');
  const ws = new WebSocket(`${wsUrl}/ws`);
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch {}
  };
  return ws;
}