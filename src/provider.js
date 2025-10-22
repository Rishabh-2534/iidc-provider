import express from 'express';
import Provider from 'oidc-provider';
import { createOIDCConfig } from './config/oidc.config.js';
import { checkBlacklist } from './middleware/blacklist.middleware.js';
import { setupRoutes } from './routes/index.js';
import ClientService from './services/client.service.js';

const PORT = process.env.PORT || 3000;
const ISSUER = process.env.ISSUER_URL || `http://localhost:${PORT}`;

const app = express();

const configuration = createOIDCConfig();
const oidc = new Provider(ISSUER, configuration);

const { Client } = oidc;
Client.find = async function(clientId) {
  const clientConfig = await ClientService.loadClient(clientId);
  if (!clientConfig) return undefined;
  return new this(clientConfig);
};

// Apply middleware ONLY to our custom routes, not OIDC provider routes
app.use('/interaction', express.urlencoded({ extended: true }));
app.use('/admin', express.json());
app.use(checkBlacklist);

setupRoutes(app, oidc);

app.use('/', oidc.callback());

app.listen(PORT, () => {
  console.log(`OIDC Provider running on ${ISSUER}`);
});
