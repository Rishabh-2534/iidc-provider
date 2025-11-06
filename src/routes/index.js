/**
 * Routes Index
 * Aggregates all application routes
 */

import InteractionController from '../controllers/interaction.controller.js';
import revocationRoutes from './revocation.routes.js';
import { getStorage } from '../config/adapter.js';

export function setupRoutes(app, oidc) {
  // Add middleware to intercept authorization requests and force offline_access
 
  // Register interaction routes directly on app (before oidc.callback())
  // Use more specific route patterns to avoid conflicts
      app.get('/interaction/:uid', async (req, res) => {
        console.log('Custom interaction route hit:', req.params.uid);
        console.log('Request URL:', req.url);
        console.log('Request query:', req.query);
        
        // Check if there's already an interaction result
        try {
          const details = await oidc.interactionDetails(req, res);
          
          // VERIFY CLIENT OBJECT
          console.log('--- VERIFY CLIENT OBJECT ---');
          console.log('ctx.oidc.client (provider view):', JSON.stringify(details?.client || req.ctx?.oidc?.client || req.oidc?.client || {}, null, 2));
          console.log('ctx.request.query.scope (raw):', req.query.scope);
          console.log('Interaction details in GET:', {
            prompt: details.prompt,
            params: details.params,
            session: details.session
          });
          
          // Serve the consent page directly from provider domain
          return InteractionController.showAuthorization(req, res, oidc);
        } catch (err) {
          console.log('Error getting interaction details:', err.message);
          return res.status(400).send('Invalid interaction');
        }
      });
  
  app.post('/interaction/:uid/callback', (req, res) => {
    console.log('Custom interaction callback route hit:', req.params.uid);
    return InteractionController.handleCallback(req, res, oidc);
  });

  // Resolve consent token for tenant-hosted consent pages
 /* app.get('/interaction/consent/resolve', (req, res) => {
    try {
      const ct = req.query.ct;
      if (!ct) return res.status(400).json({ error: 'missing_consent_token' });
      const storage = getStorage();
      const record = storage.get(`ConsentToken:${ct}`);
      if (!record) return res.status(410).json({ error: 'consent_token_expired' });
      if (record.expiresAt && Date.now() > record.expiresAt) {
        return res.status(410).json({ error: 'consent_token_expired' });
      }
      const payload = record.payload || {};
      return res.json({
        uid: payload.uid,
        clientId: payload.clientId,
        scopes: payload.scopes,
        tid: payload.tid,
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });*/


  app.use('/admin', revocationRoutes);
  
  // routes configured
}

