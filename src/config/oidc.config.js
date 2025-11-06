import { MemoryAdapter, NoopAdapter } from './adapter.js';
import { Account } from './accounts.js';
import TenantService from '../services/tenant.service.js';
import TenantDomainService from '../services/tenant-domain.service.js';
import crypto from 'crypto';
import ClientService from '../services/client.service.js';
import TokenService from '../services/token.service.js';
import BlacklistService from '../services/blacklist-service.js';
import { getStorage } from './adapter.js';
import createCustomRefreshTokenModel from '../customRefreshToken.js';

export function createOIDCConfig() {
  return {
    
    adapter: (name) => {
      /*if(name=='Session'||name==='AccessToken'||name==='ClientCredentials'){
        return new NoopAdapter(name);}
     if (name === 'RefreshToken'||name==='Grant'||name==='IdToken') {
        console.log(`🚫 Skipping persistence for ${name} using noop adapter `);
        return new NoopAdapter(name);
      }*/
      // Get tenant ID from current context (in real app, this would come from request)
      console.log(name,"AAYA @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
      const tenantId = process.env.DEFAULT_TENANT_ID || null;
      console.log(`🏢 Creating ${name} adapter for tenant: ${tenantId}`);
      return new MemoryAdapter(name, tenantId);
    },
   // findAccount: Account.findAccount,
    
   cookies: {
      keys: ['some-stable-secret'],
      long: { sameSite: 'lax' },
      short: { sameSite: 'lax' },
    },
    
    
    async extraTokenClaims(ctx, token) {
      console.log('📝 extraTokenClaims called:', {
        kind: token?.kind,
        format: token?.format,
        accountId: token?.accountId,
        clientId: token?.clientId
      });
      
      const claims = { jti: token.jti };
      
      // user-bound tokens via session/grant
      const accountId = token.accountId || ctx.oidc?.session?.accountId;
      if (accountId) {
        claims.aid = accountId;
      }
      // enforce tenant id default 
      if (!claims.tid) {
        const tid = TenantService.resolveTenantIdFromKoa(ctx);
        if (tid) claims.tid = tid;
      }
      return claims;
    },
    
    async revoked(ctx, token) {
      if (token.jti) {
        const expiresIn = token.exp 
          ? Math.max(0, token.exp - Math.floor(Date.now() / 1000))
          : 3600;
        
        await BlacklistService.add(token.jti, expiresIn, {
          clientId: token.clientId || token.aud,
          kind: token.kind,
          reason: 'standard_oauth_revocation',
        });
      }
      return false;
    },

    // Let OIDC provider handle refresh token issuance automatically
   

    
    ttl: {
      // Per-app TTLs (loaded from app details API)
      AccessToken(ctx, token, client) {
        return TokenService.getClientTokenTTL(client.clientId, 'AccessToken');
      },
      RefreshToken(ctx, token, client) {
        return TokenService.getClientTokenTTL(client.clientId, 'RefreshToken');
      },
      IdToken(ctx, token, client) {
        return TokenService.getClientTokenTTL(client.clientId, 'IdToken');
      },
      ClientCredentials(ctx, token, client) {
        return TokenService.getClientTokenTTL(client.clientId, 'ClientCredentials');
      },
      
      // Global TTLs (same for all apps)
      AuthorizationCode: 600,     // 10 minutes
      Interaction: 600,            // 10 minutes
      Session: 1209600,            // 14 days
      Grant: 1209600,              // 14 days
    },
    
    // CRITICAL: Authorization codes should NOT expire with session
    // This allows token exchange to work without session cookies
    expiresWithSession(ctx, code) {
      return false;
    },

    features: {
      devInteractions: { enabled: false },  // CRITICAL: Disable default dev interactions
      clientCredentials: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
      userinfo: { enabled: true },  // ✅ important
      
      //jwtAccessTokens: { enabled: true },
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo(ctx, resourceIndicator) {
           console.log('getResourceServerInfo called with resourceIndicator:', resourceIndicator);
            if (resourceIndicator ==='urn:api') {
                console.log('getResourceServerInfo returning resource server info for urn:api');
                return {
                    scope: 'read',
                    audience: 'urn:api',
                    accessTokenTTL: 1 * 60 * 60, // 1 hour
                    accessTokenFormat: 'jwt'
                }
            }
    
            throw new errors.InvalidTarget();
        },
     }
    },
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name', 'preferred_username'],
    },

    scopes: [
      'openid', 'profile', 'email', 'offline_access', 'read',
      'api:read', 'api:write','api:admin','internal:admin',
      // resource/API scopes used by clients in this POC
       'User:Read', 'User:ReadWrite', 'Users:Read:All', 'Sites:ReadWrite:All',
    ],
    
   interactions: {
      url: async (ctx, interaction) => {
        
        const enabled = String(process.env.ENABLE_TENANT_CONSENT || 'false').toLowerCase() === 'true';
        if (!enabled) return `/interaction/${interaction.uid}`;

        const tid = TenantService.resolveTenantIdFromKoa(ctx);
        if (!tid) return `/interaction/${interaction.uid}`;

        const ct = crypto.randomBytes(24).toString('base64url');
        const expiresAt = Date.now() + (2 * 60 * 1000);
        try {
          const storage = getStorage();
          storage.set(`ConsentToken:${ct}`, {
            payload: {
              uid: interaction.uid,
              clientId: interaction.params?.client_id,
              tid,
              scopes: interaction.params?.scope || '',
            },
            expiresAt,
            tid,
          });
        } catch (_) {}
        //for now in the poc using the existing ct in real db to avoid integration so 
        const consentToken = '0d18b00d-422e-4a69-960f-419f953f0c5d';
         
        try {
          // Support sandbox: pass sbid if your headers carry it; omitted here for brevity
          const host = await TenantDomainService.getSubdomainForTenant(tid);
          return TenantDomainService.buildConsentUrl(host, consentToken);
        } catch (error) {
          console.error('❌ Error getting tenant subdomain:', error.message);
          return `/interaction/${interaction.uid}`;
        }
        
      },
    },
    
    conformIdTokenClaims: false,
    
    async renderError(ctx, out, error) {
      console.error('OIDC Error:', error);
      ctx.type = 'html';
      ctx.body = `<!DOCTYPE html>
        <html><body>
          <h1>Authorization Error</h1>
          <p><strong>Error:</strong> ${error.error || 'unknown_error'}</p>
          <p><strong>Description:</strong> ${error.error_description || 'An error occurred'}</p>
          <p><a href="http://localhost:3001">← Back to Client</a></p>
        </body></html>`;
    },

    loadExistingGrant: async (ctx) => {
      console.log('🔍 LOAD EXISTING GRANT CALLED:');
      console.log('  Requested scopes:', ctx.oidc?.params?.scope);
      console.log('  Client ID:', ctx.oidc?.client?.clientId);
      console.log('  Session exists:', !!ctx.oidc?.session);
      console.log('  Interaction result:', ctx.oidc?.result);
      
      // First, try to find the grant from the interaction result (during continuation)
      if (ctx.oidc?.result?.consent?.grantId) {
        const grantId = ctx.oidc.result.consent.grantId;
        console.log('FOUND grant from interaction result:', grantId);
        try {
          const grant = await ctx.oidc.provider.Grant.find(grantId);
          if (grant) {
            console.log('RETURNING grant from interaction result (scope filtering handled in interaction)');
            return grant;
          }
        } catch (err) {
          console.log('ERROR finding grant:', err.message);
        }
      }
      
      // If prompt=consent is present, force consent (as requested)
      const promptParam = (ctx.oidc?.params?.prompt || '').split(' ');
      if (promptParam.includes('consent')) {
        console.log('prompt=consent detected, forcing consent page');
        return undefined;
      }
      
      // Normal flow - find existing grant from session
      const grantId = ctx.oidc.session?.grantIdFor?.(ctx.oidc.client?.clientId);
      if (grantId) {
        try {
          const grant = await ctx.oidc.provider.Grant.find(grantId);
          if (grant) {
            console.log('Found existing grant, returning it (scope filtering handled in interaction)');
            return grant;
          }
        } catch (err) {
          console.log('Grant not found or error:', err.message);
        }
      }
      
      // No grant found - will trigger consent
      console.log('No grant found, returning undefined');
      return undefined;
    },
    
    pkce: {
      methods: ['S256'],
      required: () => false,
    },
    
    // Custom function to control refresh token issuance based on user preferences
    issueRefreshToken: async (ctx, client, code) => {
      
      
      // Default behavior - issue refresh token if offline_access is requested
      const hasOfflineAccess = code.scope && code.scope.includes('offline_access');
      console.log('  Has offline_access in code scope:', hasOfflineAccess);
      console.log('  Default behavior - issuing refresh token:', hasOfflineAccess);
      return hasOfflineAccess;
    },
  };
}

