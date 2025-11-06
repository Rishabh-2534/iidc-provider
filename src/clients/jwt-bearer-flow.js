import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';

const ISSUER = 'tenant-a-web-app'; // same as your client_id
const CLIENT_SECRET = 'tenant-a-web-secret-12345';
const TOKEN_ENDPOINT = 'http://localhost:3000/token';
import { demoPrivateKeyPEM } from '../demo-key.js';

// Load private key
const privateKey = demoPrivateKeyPEM;
// Build JWT assertion (RFC 7523)
const now = Math.floor(Date.now() / 1000);
const payload = {
  iss: ISSUER,
  sub: ISSUER, // same as client_id (self-issued)
  aud: `${TOKEN_ENDPOINT}`,
  iat: now,
  exp: now + 60, // valid for 60s
  jti: `jwt-${now}`, // unique ID
};

const jwtAssertion = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

// Prepare form data for JWT Bearer flow
const params = new URLSearchParams();
params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
params.append('assertion', jwtAssertion);
params.append('scope', 'openid profile email');

// Basic auth header (client_id:client_secret)
const basicAuth = Buffer.from(`${ISSUER}:${CLIENT_SECRET}`).toString('base64');

// Make token request
const response = await fetch(TOKEN_ENDPOINT, {
  method: 'POST',
  headers: {
    'Authorization': `Basic ${basicAuth}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: params.toString(),
});

const data = await response.json();

console.log('\n🔑 JWT Assertion:', jwtAssertion);
console.log('\n✅ Token Response:', data);
