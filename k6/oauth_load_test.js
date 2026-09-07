import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom Metrics
const authSessionSuccess = new Rate('auth_session_success_rate');
const authSessionDuration = new Trend('auth_session_total_duration_ms');
const discovery304Rate = new Rate('discovery_etag_304_rate');
const jwks304Rate = new Rate('jwks_etag_304_rate');

export const options = {
  scenarios: {
    // Scenario 1: End-to-End Interactive OAuth 2.1 Auth Sessions
    // Targets continuous session throughput with concurrent virtual users
    full_oauth_session_flow: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
      exec: 'testFullAuthFlow',
    },
    // Scenario 2: High-Throughput Discovery & JWKS Caching (ETag validation)
    // Simulates resource servers and microservices constantly querying keys/metadata
    discovery_and_jwks_burst: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 50,
      stages: [
        { target: 30, duration: '10s' }, // Ramp up to 30 req/sec
        { target: 30, duration: '15s' }, // Sustain at 30 req/sec (~108,000 req/hr)
        { target: 0, duration: '5s' },   // Ramp down
      ],
      exec: 'testDiscoveryAndJwks',
    },
  },
  thresholds: {
    auth_session_success_rate: ['rate>0.95'], // At least 95% of full auth sessions must succeed
    auth_session_total_duration_ms: ['p(95)<1500'], // 95% of full multi-hop auth flows under 1.5s
    discovery_etag_304_rate: ['rate>0.90'], // At least 90% of repeat discovery requests return 304
    jwks_etag_304_rate: ['rate>0.90'], // At least 90% of repeat JWKS requests return 304
    http_req_failed: ['rate<0.05'], // Overall HTTP failure rate below 5%
  },
};

export default function () {
  testFullAuthFlow();
  testDiscoveryAndJwks();
}

// Scenario 1: Complete 6-Hop End-to-End OAuth 2.1 Session Flow
export function testFullAuthFlow() {
  const startTime = new Date().getTime();
  const jar = http.cookieJar();
  jar.clear('http://localhost:8080');
  jar.clear('http://localhost:9000');
  jar.clear('http://localhost:3000');

  // Step 0: Obtain CSRF token from Demo Client (GET /)
  let res = http.get('http://localhost:8080/', { jar: jar });
  let match = res.body.match(/name="authenticity_token" value="([^"]+)"/);
  let csrfToken = match ? match[1] : '';

  // Step 1: Start login at Demo Client (POST /auth/start)
  // Demo client pushes authorization request (PAR) to Spring AS and issues 302 redirect
  res = http.post('http://localhost:8080/auth/start', {
    flow: 'par',
    authenticity_token: csrfToken,
  }, {
    redirects: 0,
    jar: jar,
  });

  let pass = check(res, {
    '1. /auth/start returns 302/303 redirect to Spring AS': (r) => r.status === 302 || r.status === 303,
    '1. Location header contains /oauth2/authorize': (r) => r.headers['Location'] && r.headers['Location'].includes('/oauth2/authorize'),
  });

  if (!pass) {
    authSessionSuccess.add(0);
    return;
  }

  let authorizeUrl = res.headers['Location'];

  // Step 2: Request /oauth2/authorize at Spring AS
  // Spring AS detects no active user session, redirects to Rails IdP (/login?return_to=...)
  res = http.get(authorizeUrl, {
    redirects: 0,
    jar: jar,
  });

  pass = check(res, {
    '2. /oauth2/authorize redirects to Rails IdP': (r) => r.status === 302,
    '2. Redirect targets Rails /login': (r) => r.headers['Location'] && r.headers['Location'].includes('/login'),
  });

  if (!pass) {
    authSessionSuccess.add(0);
    return;
  }

  let railsLoginUrl = res.headers['Location'];

  // Extract return_to parameter
  let returnToParam = '';
  let urlParts = railsLoginUrl.split('return_to=');
  if (urlParts.length > 1) {
    returnToParam = decodeURIComponent(urlParts[1]);
  } else {
    returnToParam = authorizeUrl;
  }

  // Step 2b: GET /login at Rails IdP to obtain Rails CSRF authenticity_token
  res = http.get(railsLoginUrl, { jar: jar });
  let railsCsrfMatch = res.body.match(/name="authenticity_token" value="([^"]+)"/);
  let railsCsrfToken = railsCsrfMatch ? railsCsrfMatch[1] : '';

  // Step 3: Authenticate at Rails IdP (POST /login)
  // Rails sets SHARED_SESSION_ID cookie and redirects back to Spring AS return_to
  const payload = {
    username: `load_user_${__VU}_${__ITER}`,
    password: 'password',
    return_to: returnToParam,
    authenticity_token: railsCsrfToken,
  };

  res = http.post('http://localhost:3000/login', payload, {
    redirects: 0,
    jar: jar,
  });

  pass = check(res, {
    '3. Rails POST /login returns 303/302 redirect': (r) => r.status === 302 || r.status === 303,
    '3. Rails returns to Spring AS authorize URL': (r) => r.headers['Location'] && r.headers['Location'].includes('/oauth2/authorize'),
  });

  if (!pass) {
    authSessionSuccess.add(0);
    return;
  }

  let backToAuthorizeUrl = res.headers['Location'];

  // Step 4: Submit authenticated session to Spring AS (/oauth2/authorize)
  // Spring AS verifies SHARED_SESSION_ID from Redis, generates code, appends iss (RFC 9207),
  // and redirects to demo client callback (/auth/callback?code=...&iss=...)
  res = http.get(backToAuthorizeUrl, {
    redirects: 0,
    jar: jar,
  });

  pass = check(res, {
    '4. Spring AS issues authorization code': (r) => r.status === 302,
    '4. Redirects to Demo Client callback with code': (r) => r.headers['Location'] && r.headers['Location'].includes('/callback'),
  });

  if (!pass) {
    authSessionSuccess.add(0);
    return;
  }

  let callbackUrl = res.headers['Location'];

  // Step 5: Demo Client processes callback (/callback)
  // Demo client validates iss, executes token exchange (code + private_key_jwt + DPoP),
  // validates ID token against cached JWKS, fetches UserInfo, stores session in Redis DB 1,
  // and redirects to /profile
  res = http.get(callbackUrl, {
    redirects: 0,
    jar: jar,
  });

  pass = check(res, {
    '5. Callback exchanges code and sets session': (r) => r.status === 302,
    '5. Redirects to demo client profile': (r) => r.headers['Location'] && r.headers['Location'].includes('/profile'),
  });

  if (!pass) {
    authSessionSuccess.add(0);
    return;
  }

  // Step 6: Access protected Demo Client Profile (/profile)
  res = http.get('http://localhost:8080/profile', {
    redirects: 0,
    jar: jar,
  });

  pass = check(res, {
    '6. Profile renders authenticated user state': (r) => r.status === 200,
  });

  const duration = new Date().getTime() - startTime;
  authSessionDuration.add(duration);
  authSessionSuccess.add(pass ? 1 : 0);

  // Pacing pause between simulated user sessions
  sleep(0.5);
}

// Scenario 2: Discovery & JWKS Caching and HTTP 304 Validation
export function testDiscoveryAndJwks() {
  // Test Discovery Endpoint
  const discUrl = 'http://localhost:9000/.well-known/openid-configuration';
  let discRes = http.get(discUrl);

  let etag = discRes.headers['Etag'] || discRes.headers['ETag'];
  if (etag) {
    // Send conditional request
    let cachedRes = http.get(discUrl, {
      headers: { 'If-None-Match': etag },
    });
    discovery304Rate.add(cachedRes.status === 304 ? 1 : 0);
    check(cachedRes, {
      'Discovery returns 304 on matching ETag': (r) => r.status === 304,
    });
  }

  // Test JWKS Endpoint
  const jwksUrl = 'http://localhost:9000/oauth2/jwks';
  let jwksRes = http.get(jwksUrl);

  let jwksEtag = jwksRes.headers['Etag'] || jwksRes.headers['ETag'];
  if (jwksEtag) {
    let cachedJwksRes = http.get(jwksUrl, {
      headers: { 'If-None-Match': jwksEtag },
    });
    jwks304Rate.add(cachedJwksRes.status === 304 ? 1 : 0);
    check(cachedJwksRes, {
      'JWKS returns 304 on matching ETag': (r) => r.status === 304,
    });
  }
}
