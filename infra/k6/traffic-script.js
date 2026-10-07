import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  scenarios: {
    steady_traffic: {
      executor: 'constant-vus',
      vus: 3,
      duration: '10m',
    },
  },
};

export default function () {
  http.get('http://127.0.0.1:8080/trigger');
  sleep(Math.random() * 2 + 1); // 1-3s between calls, varied timing
}
