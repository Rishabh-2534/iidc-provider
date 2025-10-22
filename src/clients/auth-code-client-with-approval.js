import express from 'express';
import axios from 'axios';
import { URLSearchParams } from 'url';
import crypto from 'crypto';

const CLIENT_ID = 'tenant-a-web-app';
const CLIENT_SECRET = 'tenant-a-web-secret-12345';
const REDIRECT_URI = 'http://localhost:3001/callback';
const AUTHORIZATION_URI = 'http://localhost:3001/authorize';
const ISSUER = 'http://localhost:3000';
const CALLBACK_PORT = 3001;

const AUTHORIZATION_ENDPOINT = `${ISSUER}/auth`;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const USERINFO_ENDPOINT = `${ISSUER}/me`;

const state = crypto.randomBytes(16).toString('hex');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

let tokens = null;
let pendingInteraction = null;

app.get('/', (req, res) => {
  const authParams = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile offline_access',//remove offline_access for only access token
    state: state,
  });

  const authUrl = `${AUTHORIZATION_ENDPOINT}?${authParams.toString()}`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OIDC Demo Client</title>
      <style>
        body { font-family: Arial; max-width: 600px; margin: 100px auto; text-align: center; background: #f5f5f5; padding: 20px; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .login-btn { background: #007bff; color: white; padding: 15px 30px; border: none; border-radius: 4px; font-size: 18px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 20px; }
        .login-btn:hover { background: #0056b3; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔐 OIDC Provider Demo</h1>
        <p>Authorization Code Flow with Custom Approval Page</p>
        
        <div class="info">
          <strong>Client ID:</strong> ${CLIENT_ID}<br>
          <strong>Scopes:</strong> openid, email, profile
        </div>
        
        <a href="${authUrl}" class="login-btn">
          🚀 Login with OIDC Provider
        </a>
        
        <p style="margin-top: 30px; color: #666; font-size: 14px;">
          You'll be redirected to authorize this application
        </p>
      </div>
    </body>
    </html>
  `);
});

app.get('/authorize', (req, res) => {
  const { interaction_uid, client_id, scope, redirect_uri, state } = req.query;
  
  pendingInteraction = { interaction_uid, client_id, scope, redirect_uri, state };
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authorize Application</title>
      <style>
        body { font-family: Arial; max-width: 500px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .auth-box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h2 { color: #333; text-align: center; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .user-select { margin: 20px 0; }
        select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin-top: 10px; }
        .buttons { display: flex; gap: 10px; margin-top: 20px; }
        button { flex: 1; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .approve { background: #28a745; color: white; }
        .deny { background: #dc3545; color: white; }
        .scope-list { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .scope-item { padding: 5px 0; border-bottom: 1px solid #dee2e6; }
        .scope-item:last-child { border-bottom: none; }
      </style>
    </head>
    <body>
      <div class="auth-box">
        <h2>Authorization Request</h2>
        
        <div class="info">
          <strong>Application:</strong> ${client_id}<br>
          <strong>Redirect URI:</strong> ${redirect_uri}
        </div>
        
        <div class="scope-list">
          <strong>Requested Permissions:</strong>
          ${(scope || '').split(' ').map(s => `<div class="scope-item">✓ ${s}</div>`).join('')}
        </div>
        
        <div class="user-select">
          <label><strong>Select User:</strong></label>
          <select id="userId">
            <option value="">-- Select User --</option>
            <option value="user1">User 1 (user1@example.com)</option>
            <option value="user2">User 2 (user2@example.com)</option>
          </select>
        </div>
        
        <div class="buttons">
          <button class="approve" onclick="approve()">Approve</button>
          <button class="deny" onclick="deny()">Deny</button>
        </div>
      </div>
      
      <script>
        function approve() {
          const userId = document.getElementById('userId').value;
          if (!userId) {
            alert('Please select a user');
            return;
          }
          
          const form = document.createElement('form');
          form.method = 'POST';
          form.action = '${ISSUER}/interaction/${interaction_uid}/callback';
          
          const approvedField = document.createElement('input');
          approvedField.type = 'hidden';
          approvedField.name = 'approved';
          approvedField.value = 'true';
          form.appendChild(approvedField);
          
          const userIdField = document.createElement('input');
          userIdField.type = 'hidden';
          userIdField.name = 'user_id';
          userIdField.value = userId;
          form.appendChild(userIdField);
          
          document.body.appendChild(form);
          form.submit();
        }
        
        function deny() {
          const form = document.createElement('form');
          form.method = 'POST';
          form.action = '${ISSUER}/interaction/${interaction_uid}/callback';
          
          const deniedField = document.createElement('input');
          deniedField.type = 'hidden';
          deniedField.name = 'denied';
          deniedField.value = 'true';
          form.appendChild(deniedField);
          
          document.body.appendChild(form);
          form.submit();
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/approve', async (req, res) => {
  const { interaction_uid, user_id, approved, denied } = req.body;
  
  try {
    const response = await axios.post(
      `${ISSUER}/interaction/${interaction_uid}/callback`,
      new URLSearchParams({
        approved: approved ? 'true' : 'false',
        user_id: user_id || '',
        denied: denied ? 'true' : 'false',
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Cookie': req.headers.cookie || '',
        },
        maxRedirects: 0,
        validateStatus: () => true,
      }
    );
    
    console.log('Response status:', response.status);
    console.log('Response headers:', response.headers);
    
    const redirectUrl = response.headers.location || response.headers.Location;
    console.log('Redirect URL:', redirectUrl);
    
    if (redirectUrl) {
      res.json({ success: true, redirectUrl });
    } else {
      res.status(500).json({ error: 'No redirect URL', status: response.status, headers: response.headers });
    }
  } catch (error) {
    console.error('Approve error:', error.message);
    res.status(500).json({ error: error.message, details: error.response?.data });
  }
});

app.get('/callback', async (req, res) => {
  try {
    const { code, state: returnedState, error, error_description } = req.query;

    if (error) {
      return res.send(`<h2>Error: ${error}</h2><p>${error_description}</p>`);
    }

    if (returnedState !== state) {
      return res.send('<h2>State mismatch error</h2>');
    }

    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });

    const tokenResponse = await axios.post(TOKEN_ENDPOINT, tokenParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    tokens = tokenResponse.data;

    const userInfoResponse = await axios.get(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const userInfo = userInfoResponse.data;

    res.send(`
      <html>
      <head>
        <title>Success</title>
        <style>
          body { font-family: Arial; padding: 50px; max-width: 800px; margin: 0 auto; }
          .success { background: #d4edda; padding: 20px; border-radius: 8px; }
          h2 { color: #155724; }
          pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <div class="success">
          <h2>✅ Authorization Successful</h2>
          <h3>Access Token:</h3>
          <pre>${tokens.access_token.substring(0, 50)}...</pre>
          ${tokens.refresh_token ? `<h3>Refresh Token:</h3><pre>${tokens.refresh_token.substring(0, 50)}...</pre>` : ''}
          ${tokens.id_token ? `<h3>ID Token:</h3><pre>${tokens.id_token.substring(0, 50)}...</pre>` : ''}
          <h3>Token Details:</h3>
          <pre>${JSON.stringify({
            token_type: tokens.token_type,
            expires_in: tokens.expires_in,
            scope: tokens.scope
          }, null, 2)}</pre>
          <h3>User Info:</h3>
          <pre>${JSON.stringify(userInfo, null, 2)}</pre>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    res.send(`<h2>Error</h2><pre>${JSON.stringify(error.response?.data || error.message, null, 2)}</pre>`);
  }
});

const server = app.listen(CALLBACK_PORT, () => {
  console.log(`OIDC Demo Client Running on http://localhost:${CALLBACK_PORT}`);
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
