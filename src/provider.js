import express from 'express';
import Provider from 'oidc-provider';
import { createOIDCConfig } from './config/oidc.config.js';
import { checkBlacklist } from './middleware/blacklist.middleware.js';
import { setupRoutes } from './routes/index.js';
import ClientService from './services/client.service.js';
import jwtBearerHandler from './jwt-bearer-handler.js';
const PORT = process.env.PORT || 3000;
const ISSUER = process.env.ISSUER_URL || `http://localhost:${PORT}`;

const app = express();

const configuration = createOIDCConfig();
const oidc = new Provider(ISSUER, configuration);

// Override Client.find to use dynamic loading from config service with tenant context
const { Client } = oidc;
Client.find = async function(clientId, tenantId ) {
  // Get tenant ID from current context if not provided
  const currentTenantId = tenantId || process.env.DEFAULT_TENANT_ID || null;
  const clientConfig = await ClientService.loadClient(clientId, currentTenantId);
  console.log('CLIENT.FIND DEBUG:');
  console.log('  Client ID:', clientConfig.client_id);
  console.log('  Client scope:', clientConfig.scope);
  console.log('  Client grant types:', clientConfig.grant_types);
  console.log('  Tenant ID:', currentTenantId);
  const client = new this(clientConfig);// this is the client object that is used to authenticate the client
  client.tenantId = currentTenantId;
  return client;
};

const jwtBearerGrantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const jwtBearerParams = ['assertion', 'scope'];
oidc.registerGrantType(jwtBearerGrantType, jwtBearerHandler, jwtBearerParams);

// Apply middleware ONLY to our custom routes, not OIDC provider routes
app.use('/interaction', express.urlencoded({ extended: true }));
//app.use('/admin', express.json());x
app.use(checkBlacklist);

// OIDC provider handles scope validation automatically

// Set up custom routes BEFORE OIDC callback middleware
setupRoutes(app, oidc);


// Apply OIDC callback middleware to all other routes
app.use('/', oidc.callback());  

app.listen(PORT, () => {
  console.log(`OIDC Provider running on ${ISSUER}`);
});
