import { MemoryAdapter } from './adapter.js';
import { Account } from './accounts.js';
import ClientService from '../services/client.service.js';
import TokenService from '../services/token.service.js';
import BlacklistService from '../services/blacklist-service.js';

export function createOIDCConfig() {
  return {
    clients: [],
    adapter: MemoryAdapter,
    findAccount: Account.findAccount,
    
    cookies: {
      keys: ['some-secret-key-for-cookies-signing'],
      long: { sameSite: 'lax' },
      short: { sameSite: 'lax' },
    },
    
    formats: {
      AccessToken: 'jwt',
      ClientCredentials: 'jwt',
      RefreshToken: 'jwt',
    },
    
    async extraTokenClaims(ctx, token) {
      return { jti: token.jti };
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

    async issueRefreshToken(ctx, client, code) {
      const requestedScopes = new Set((ctx.oidc?.params?.scope || '').split(' ').filter(Boolean));
      const hasOfflineRequested = requestedScopes.has('offline_access');
      const clientAllowsOffline = ((client?.scope || '').split(' ').includes('offline_access'));
      
      if (!client.grantTypes.includes('refresh_token')) return false;

      if (code.kind === 'AuthorizationCode') {
        // Enforce per-user policy via account flag
        const accountId = code.accountId || ctx.oidc?.session?.accountId;
        const account = accountId ? await Account.findAccount(ctx, accountId) : null;
        const isOfflineAllowed = Boolean(account?.allowOfflineAccess);
        const hasOfflineAccess = (code.scopes.has('offline_access') || hasOfflineRequested || clientAllowsOffline) && isOfflineAllowed;
        return hasOfflineAccess;
      }
      return true;
    },
    
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
      devInteractions: { enabled: false },
      clientCredentials: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
      resourceIndicators: { enabled: false },
    },

    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name', 'preferred_username'],
    },

    scopes: [
      'openid', 'profile', 'email', 'offline_access',
      // resource/API scopes used by clients in this POC
      'api:read', 'api:write', 'api:admin', 'internal:admin',
    ],

    interactions: {
      url(ctx, interaction) {
        return `/interaction/${interaction.uid}`;
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
      const grantId = 
        ctx.oidc.result?.consent?.grantId || 
        ctx.oidc.session?.grantIdFor?.(ctx.oidc.client?.clientId);
      
      if (grantId) {
        try {
          const grant = await ctx.oidc.provider.Grant.find(grantId);
          if (grant) {
            // Merge any newly requested scopes into the existing grant (including offline_access)
            if (ctx.oidc.params?.scope) {
              const scopes = ctx.oidc.params.scope.split(' ');
              const standardOIDCScopes = ['openid', 'offline_access', 'profile', 'email', 'address', 'phone'];
              const accountId = ctx.oidc.session?.accountId;
              const account = accountId ? await Account.findAccount(ctx, accountId) : null;
              const isOfflineAllowed = Boolean(account?.allowOfflineAccess);
              const oidcScopes = scopes
                .filter((s) => standardOIDCScopes.includes(s))
                .filter((s) => s !== 'offline_access' || isOfflineAllowed);
              const resourceScopes = scopes.filter((s) => !standardOIDCScopes.includes(s));

              if (oidcScopes.length > 0) {
                grant.addOIDCScope(oidcScopes.join(' '));
              }
              if (resourceScopes.length > 0) {
                grant.addResourceScope('', resourceScopes.join(' '));
              }
              await grant.save();
            }
            return grant;
          }
        } catch (err) {
          // Grant not found or error loading
        }
      }
      
      // If no grant found, create a new one to skip consent
      if (ctx.oidc.session?.accountId && ctx.oidc.client) {
        const grant = new ctx.oidc.provider.Grant({
          accountId: ctx.oidc.session.accountId,
          clientId: ctx.oidc.client.clientId,
        });
        
        // Add all requested scopes
        if (ctx.oidc.params?.scope) {
          const scopes = ctx.oidc.params.scope.split(' ');
          const standardOIDCScopes = ['openid', 'offline_access', 'profile', 'email', 'address', 'phone'];
          const oidcScopes = scopes.filter(s => standardOIDCScopes.includes(s));
          const resourceScopes = scopes.filter(s => !standardOIDCScopes.includes(s));
          
          if (oidcScopes.length > 0) {
            grant.addOIDCScope(oidcScopes.join(' '));
          }
          if (resourceScopes.length > 0) {
            grant.addResourceScope('', resourceScopes.join(' '));
          }
        }
        
        await grant.save();
        return grant;
      }
      
      return undefined;
    },

    pkce: {
      methods: ['S256'],
      required: () => false,
    },
  };
}

