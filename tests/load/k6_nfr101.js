/**
 * NFR-101 — P99 < 10ms at 1,000 RPS for 5 minutes (gateway POST /)
 *
 * Prerequisites:
 *   docker compose up -d --build
 *   ALLOW_WILDCARD_IDENTITY=false for realistic auth (optional: set OIDC_TOKEN)
 *
 * Run:
 *   export OIDC_TOKEN=$(curl -s "http://localhost:8081/token?sub=load&aud=agentwall" | jq -r .access_token)
 *   k6 run tests/load/k6_nfr101.js
 */
import http from 'k6/http';
import { check } from 'k6';

const TOKEN = __ENV.OIDC_TOKEN || '';
const URL = __ENV.GATEWAY_URL || 'http://localhost:8080/';
const TOOL = __ENV.TOOL_NAME || 'safe_tool';

export const options = {
  scenarios: {
    constant_1k: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(99)<10'],
  },
};

export default function () {
  const payload = JSON.stringify({
    jsonrpc: '2.0',
    id: __VU,
    method: 'tools/call',
    params: { name: TOOL, arguments: { example: 'load' } },
  });
  const headers = { 'Content-Type': 'application/json' };
  if (TOKEN) {
    headers.Authorization = `Bearer ${TOKEN}`;
  }
  const res = http.post(URL, payload, { headers });
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
