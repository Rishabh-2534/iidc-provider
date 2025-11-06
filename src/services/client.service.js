import axios from 'axios';
import TokenService from './token.service.js';

const CONFIG_API = process.env.CONFIG_SERVICE_URL || 'http://localhost:4000';
const CACHE_TTL = 60000;

const clientCache = new Map();

class ClientService {
  static mapClientConfig(clientData) {
    const grantTypes = [];
    const responseTypes = [];
    const redirectUris = [];
    const allowedScopes = new Set();
    
    if (clientData.config?.authorizationCodeGrant?.isEnabled) {
      grantTypes.push('authorization_code', 'refresh_token');
      responseTypes.push('code');
      redirectUris.push(...(clientData.config.authorizationCodeGrant.redirectUris || []));
      if (clientData.redirect_uri) {
        redirectUris.push(clientData.redirect_uri);
      }
      // Add allowed scopes from auth code grant
      (clientData.config.authorizationCodeGrant.allowedScopes || []).forEach(s => allowedScopes.add(s));
    }
    
    if (clientData.config?.clientCredentialsGrant?.isEnabled) {
      grantTypes.push('client_credentials');
      // Add allowed scopes from client credentials grant
      (clientData.config.clientCredentialsGrant.allowedScopes || []).forEach(s => allowedScopes.add(s));
    }
    
    // Check for JWT Bearer grant type from auth_grant_type field
    if (clientData.auth_grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      grantTypes.push('urn:ietf:params:oauth:grant-type:jwt-bearer');
    }
    
      const config = {
        client_id: clientData.client_id,
        client_secret: clientData.client_secret,
        redirect_uris: [...new Set(redirectUris)],
        response_types: responseTypes,
        grant_types: grantTypes,
        scope: Array.from(allowedScopes).join(' '),
        token_endpoint_auth_method: 'client_secret_post',
        require_signed_request_object: false,
        require_pushed_authorization_requests: false,
        backchannelLogout: undefined,
      };
      
    
    // mapped client config ready
    
    return config;
  }

  static async loadClient(clientId, tenantId = null) {
    // Create tenant-aware cache key
    const cacheKey = tenantId ? `${tenantId}:${clientId}` : clientId;
    const cached = clientCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      console.log(`📋 [CLIENT] Using cached client ${clientId} for tenant: ${tenantId}`);
      return cached.client;
    }
    
    try {
      const headers = {};
      if (tenantId) {
        headers['x-smtip-tid'] = tenantId;
        headers['x-smtip-cid'] = `oidc-provider-${Date.now()}`;
      }
      
      const response = await axios.get(`${CONFIG_API}/api/clients/${clientId}`, {
        timeout: 5000,
        headers,
      });
      
      if (!response.data) {
        return undefined;
      }
      
      const client = this.mapClientConfig(response.data);
      
      // Add tenant context to client
      if (tenantId) {
        client.tenantId = tenantId;
      }
      
      // Cache TTLs from the same response (no separate API call needed!)
      TokenService.cacheClientTTL(clientId, response.data.config);
      
      clientCache.set(cacheKey, {
        client,
        timestamp: Date.now(),
      });
      
      console.log(`📋 [CLIENT] Loaded client ${clientId} for tenant: ${tenantId}`);
      return client;
    } catch (error) {
      console.error(`❌ [CLIENT] Error loading client ${clientId} for tenant ${tenantId}:`, error.message);
      return undefined;
    }
  }

  static async getClientDetails(clientId) {
    try {
      const response = await axios.get(
        `${CONFIG_API}/api/clients/${clientId}`,
        { timeout: 5000 }
      );
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  static clearCache() {
    const size = clientCache.size;
    clientCache.clear();
    return size;
  }
}

export default ClientService;

