/**
 * Configuration Service API
 * 
 * This service provides dynamic client configurations for the OIDC provider.
 * In a real environment, this would be your centralized configuration management service.
 * 
 * Features:
 * - Multi-tenant client configurations
 * - Per-client token TTL settings
 * - Dynamic client registration
 * - Client metadata management
 */

import express from 'express';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

const CONFIG_PORT = 4000;

// In-memory configuration store (in production, this would be a database)
// Structure matches actual API response format
const tenantConfigurations = {
  'tenant-a': {
    tenantId: 'tenant-a',
    tenantName: 'Acme Corporation',
    clients: [
      {
        app_id: 'tenant-a-web-app',
        app_disp_name: 'Acme Web Application',
        app_desc: 'Acme web application for user authentication',
        type: 'custom',
        client_id: 'tenant-a-web-app',
        client_secret: 'tenant-a-web-secret-12345',
        redirect_uri: 'http://localhost:3001/callback',
        auth_grant_type: 'Authorization Code',
        state_param_supported: true,
        account_id: 'acme-account-001',
        authorization_uri: 'http://localhost:3001/authorize', // App's authorization page
        config: {
          authorizationCodeGrant: {
            isEnabled: true,
            redirectUris: ['http://localhost:3001/callback'],
            allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
            supportStateParameter: true,
            accessTokenLifeInSeconds: 7200,      // 2 hours
            refreshTokenLifeInSeconds: 604800,    // 7 days
            refreshTokenValidIfUsedInTheLastXSeconds: null,
          },
          clientCredentialsGrant: {
            isEnabled: false,
            allowedScopes: [],
            accessTokenLifeInSeconds: null,
          },
        },
      },
      {
        app_id: 'tenant-a-api-client',
        app_disp_name: 'Acme API Service',
        app_desc: 'Acme API service for server-to-server communication',
        type: 'custom',
        client_id: 'tenant-a-api-client',
        client_secret: 'tenant-a-api-secret-12345',
        redirect_uri: null,
        auth_grant_type: 'Client Credentials',
        state_param_supported: false,
        account_id: 'acme-account-001',
        config: {
          authorizationCodeGrant: {
            isEnabled: false,
            redirectUris: [],
            allowedScopes: [],
            supportStateParameter: null,
            accessTokenLifeInSeconds: null,
            refreshTokenLifeInSeconds: null,
            refreshTokenValidIfUsedInTheLastXSeconds: null,
          },
          clientCredentialsGrant: {
            isEnabled: true,
            allowedScopes: ['api:read', 'api:write', 'api:admin'],
            accessTokenLifeInSeconds: 3600,  // 1 hour
          },
        },
      },
      {
        app_id: 'tenant-a-mobile-app',
        app_disp_name: 'Acme Mobile App',
        app_desc: 'Acme mobile application for iOS and Android',
        type: 'custom',
        client_id: 'tenant-a-mobile-app',
        client_secret: 'tenant-a-mobile-secret-12345',
        redirect_uri: 'com.acme.app://callback',
        auth_grant_type: 'Authorization Code',
        state_param_supported: true,
        account_id: 'acme-account-001',
        config: {
          authorizationCodeGrant: {
            isEnabled: true,
            redirectUris: ['com.acme.app://callback'],
            allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
            supportStateParameter: true,
            accessTokenLifeInSeconds: 1800,       // 30 minutes
            refreshTokenLifeInSeconds: 2592000,   // 30 days
            refreshTokenValidIfUsedInTheLastXSeconds: null,
          },
          clientCredentialsGrant: {
            isEnabled: false,
            allowedScopes: [],
            accessTokenLifeInSeconds: null,
          },
        },
      },
    ],
  },
  'tenant-b': {
    tenantId: 'tenant-b',
    tenantName: 'Beta Industries',
    clients: [
      {
        app_id: 'tenant-b-web-app',
        app_disp_name: 'Beta Web Portal',
        app_desc: 'Beta web portal for customer access',
        type: 'custom',
        client_id: 'tenant-b-web-app',
        client_secret: 'tenant-b-web-secret-67890',
        redirect_uri: 'http://localhost:3002/callback',
        auth_grant_type: 'Authorization Code',
        state_param_supported: true,
        account_id: 'beta-account-002',
        authorization_uri: 'http://localhost:3002/authorize',
        config: {
          authorizationCodeGrant: {
            isEnabled: true,
            redirectUris: ['http://localhost:3002/callback'],
            allowedScopes: ['openid', 'profile', 'email'],
            supportStateParameter: true,
            accessTokenLifeInSeconds: 3600,       // 1 hour
            refreshTokenLifeInSeconds: 86400,     // 1 day
            refreshTokenValidIfUsedInTheLastXSeconds: null,
          },
          clientCredentialsGrant: {
            isEnabled: false,
            allowedScopes: [],
            accessTokenLifeInSeconds: null,
          },
        },
      },
      {
        app_id: 'tenant-b-api-client',
        app_disp_name: 'Beta API Service',
        app_desc: 'Beta API service for backend integration',
        type: 'custom',
        client_id: 'tenant-b-api-client',
        client_secret: 'tenant-b-api-secret-67890',
        redirect_uri: null,
        auth_grant_type: 'Client Credentials',
        state_param_supported: false,
        account_id: 'beta-account-002',
        config: {
          authorizationCodeGrant: {
            isEnabled: false,
            redirectUris: [],
            allowedScopes: [],
            supportStateParameter: null,
            accessTokenLifeInSeconds: null,
            refreshTokenLifeInSeconds: null,
            refreshTokenValidIfUsedInTheLastXSeconds: null,
          },
          clientCredentialsGrant: {
            isEnabled: true,
            allowedScopes: ['api:read', 'api:write'],
            accessTokenLifeInSeconds: 7200,  // 2 hours
          },
        },
      },
    ],
  },
  'tenant-c': {
    tenantId: 'tenant-c',
    tenantName: 'Gamma Enterprises',
    clients: [
      {
        app_id: 'tenant-c-microservice',
        app_disp_name: 'Gamma Microservice',
        app_desc: 'Gamma internal microservice for high-security operations',
        type: 'custom',
        client_id: 'tenant-c-microservice',
        client_secret: 'tenant-c-micro-secret-11111',
        redirect_uri: null,
        auth_grant_type: 'Client Credentials',
        state_param_supported: false,
        account_id: 'gamma-account-003',
        config: {
          authorizationCodeGrant: {
            isEnabled: false,
            redirectUris: [],
            allowedScopes: [],
            supportStateParameter: null,
            accessTokenLifeInSeconds: null,
            refreshTokenLifeInSeconds: null,
            refreshTokenValidIfUsedInTheLastXSeconds: null,
          },
          clientCredentialsGrant: {
            isEnabled: true,
            allowedScopes: ['api:read', 'api:write', 'internal:admin'],
            accessTokenLifeInSeconds: 900,  // 15 minutes - high security
          },
        },
      },
    ],
  },
};

// ========================================
// ESSENTIAL ENDPOINTS (Used by OIDC Provider)
// ========================================

// Get specific client configuration (used by ClientService.loadClient)
app.get('/api/clients/:clientId', (req, res) => {
  const { clientId } = req.params;
  
  for (const tenant of Object.values(tenantConfigurations)) {
    const client = tenant.clients.find(c => c.client_id === clientId);
    if (client) {
      return res.json({
        ...client,
        tenantId: tenant.tenantId,
        tenantName: tenant.tenantName,
      });
    }
  }
  
  res.status(404).json({
    error: 'not_found',
    message: `Client ${clientId} not found`,
  });
});

// Start server
app.listen(CONFIG_PORT, () => {
  console.log(`\n🔧 Configuration Service running on http://localhost:${CONFIG_PORT}`);
  console.log(`\n📋 Essential Endpoint:`);
  console.log(`   GET  /api/clients/:id - Get client configuration (includes TTL settings)`);
  console.log(`\n👥 Configured tenants: ${Object.keys(tenantConfigurations).length}`);
  console.log(`   - ${Object.values(tenantConfigurations).map(t => `${t.tenantName} (${t.tenantId})`).join('\n   - ')}`);
  console.log('');
});

