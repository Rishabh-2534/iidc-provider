import axios from 'axios';
import { URLSearchParams } from 'url';

const CLIENT_ID = 'tenant-a-api-client';
const CLIENT_SECRET = 'tenant-a-api-secret-12345';
const ISSUER = 'http://localhost:3000';

const TOKEN_ENDPOINT = `${ISSUER}/token`;
const INTROSPECTION_ENDPOINT = `${ISSUER}/token/introspection`;

async function runClientCredentialsFlow() {
  try {
    const tokenParams = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api:read api:write',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });

    const tokenResponse = await axios.post(TOKEN_ENDPOINT, tokenParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const tokens = tokenResponse.data;
    
    console.log('\nAccess Token:', tokens.access_token.substring(0, 30), '...');
    console.log('Token Type:', tokens.token_type);
    console.log('Expires In:', tokens.expires_in, 's');
    console.log('Scope:', tokens.scope || 'N/A');

    const introspectionParams = new URLSearchParams({
      token: tokens.access_token,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });

    const introspectionResponse = await axios.post(
      INTROSPECTION_ENDPOINT,
      introspectionParams.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    console.log('\nIntrospection:', JSON.stringify(introspectionResponse.data, null, 2));
    console.log('\n✅ Client Credentials Flow completed\n');

  } catch (error) {
    console.error('\nError:', error.response?.data || error.message);
    process.exit(1);
  }
}

runClientCredentialsFlow();
