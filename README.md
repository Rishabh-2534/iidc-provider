# OIDC Provider - Simple POC

Complete OAuth 2.0 / OpenID Connect provider with token revocation.

## What This Does

This is a **Token Issuer** for accessing your Simpplr APIs/services:

✅ **Issues Access Tokens** - For calling your APIs  
✅ **Issues Refresh Tokens** - To get new access tokens  
✅ **Token Revocation** - Revoke access by userId or clientId  
✅ **Dynamic Config** - Per-app token settings from API

**How it works:** Apps get tokens from this provider → Use tokens to access your Simpplr APIs

## 📚 Documentation

This README describes the current POC. Extra markdowns were removed for simplicity.

## Features

✅ **Authorization Code Flow** (3-legged OAuth) - For web/mobile apps  
✅ **Client Credentials Flow** - For service-to-service access  
✅ **Token Revocation** - Revoke by userId, clientId, or both  
✅ **Per-Client Token TTL** - Different expiry times per app  
✅ **Dynamic Client Loading** 🚀 - No restart for new clients  
✅ **Smart Caching** - 1-minute cache reduces API calls

## Quick Start

```bash
# 1. Install
npm install

# 2. Start services
npm run config-service &
npm start &

# That's it! Provider running on http://localhost:3000
```

## Test It

```bash
# Authorization Code (browser)
node src/clients/auth-code-client-with-approval.js
# Open http://localhost:3001 and follow the flow

# Client Credentials (service-to-service)
node src/clients/client-credentials-client.js
```

## Token Revocation

### Standard OAuth Revocation (Provided by Library)

```bash
# Revoke a specific token (standard OAuth 2.0)
curl -X POST http://localhost:3000/token/revocation \
  -d "token=eyJ..." \
  -d "client_id=my-app" \
  -d "client_secret=secret"
```

### Custom Revocation (Admin endpoints we provide)

```bash
# Revoke all tokens for a user (custom admin feature)
curl -X POST http://localhost:3000/admin/revoke/user/user1

# Revoke all tokens for a client (custom admin feature)
curl -X POST http://localhost:3000/admin/revoke/client/tenant-a-api-client

# Check active tokens (from in-memory adapter)
curl http://localhost:3000/admin/tokens/user/user1

# Check tokens for a client
curl http://localhost:3000/admin/tokens/client/tenant-a-api-client
```

**How it works:**
- Each token has a `jti` claim (token ID)
- Bulk revocation finds all tokens for user/client
- Adds all `jti` values to blacklist (simulating Redis)
- Middleware checks blacklist on every request
- Blacklisted tokens automatically expire after TTL

## Token TTLs & Dynamic Clients

- Per-app TTLs come from the config service and are cached for 60s.
- Clients are loaded on demand; no restart needed to add/update a client.

## How It Works

```
App/Service                OIDC Provider              Simpplr APIs
    │                           │                          │
    │ 1. Get access token       │                          │
    │──────────────────────────►│                          │
    │                           │                          │
    │ 2. Returns access token   │                          │
    │◄──────────────────────────│                          │
    │                           │                          │
    │ 3. Call API with token    │                          │
    │──────────────────────────────────────────────────────►
    │                           │                          │
    │                           │ 4. Validates token       │
    │                           │◄─────────────────────────│
    │                           │                          │
    │ 5. Returns API data       │                          │
    │◄──────────────────────────────────────────────────────
```

1. **Apps request tokens** from OIDC Provider (this POC)
2. **OIDC Provider issues** access tokens + refresh tokens
3. **Apps use tokens** to call your Simpplr APIs
4. **Simpplr APIs validate** tokens with OIDC Provider
5. **OIDC Provider can revoke** tokens anytime

## Project Structure

```
src/
├── provider.js                      # Main OIDC server (uses node-oidc-provider)
├── services/
│   └── config-service.js            # Config API (app details)
├── config/
│   ├── adapter.js                   # Token storage
│   └── accounts.js                  # User accounts
└── clients/                         # Example clients
    ├── auth-code-client-with-approval.js  # 3-legged OAuth
    ├── client-credentials-client.js       # Service-to-service
```

## Endpoints

### OIDC Provider (http://localhost:3000)

**OAuth/OIDC Endpoints (served by library):**
- `GET /auth` - Start authorization
- `POST /token` - Token endpoint (code, refresh_token, client_credentials)
- `POST /token/introspection` - Token introspection
- `POST /token/revocation` - Token revocation (RFC 7009)
- `GET /me` - UserInfo
- `GET /.well-known/openid-configuration` - Discovery

**Revocation Endpoints:**
- `POST /admin/revoke/user/:userId` - Revoke user tokens
- `POST /admin/revoke/client/:clientId` - Revoke client tokens
- `POST /admin/revoke/user/:userId/client/:clientId` - Revoke specific
- `GET /admin/tokens/user/:userId` - List user tokens
- `GET /admin/tokens/client/:clientId` - List client tokens

### Config API (http://localhost:4000)

- `GET /api/clients` - List all clients
- `GET /api/clients/:clientId` - Get client config
- `POST /api/tenants/:tenantId/clients` - Register client

## Configuration

Apps are configured in `src/services/config-service.js`:

```javascript
{
  client_id: 'my-app',
  client_secret: 'my-secret',
  grant_types: ['authorization_code', 'refresh_token'],
  token_settings: {
    accessTokenTTL: 3600,  // 1 hour
    refreshTokenTTL: 86400, // 24 hours
  }
}
```

## Use Cases

### Authorization Code Flow
- **user1**: no offline_access → access token only
- **user2**: offline_access allowed → access + refresh

### Client Credentials Flow
- Machine-to-machine access; JWT access token issued


## Troubleshooting

**Port already in use?**
```bash
lsof -ti:3000 | xargs kill
lsof -ti:4000 | xargs kill
```

**Services not starting?**
- Make sure you ran `npm install`
- Check both services are running on ports 3000 and 4000

## License

MIT

