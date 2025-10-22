/**
 * Routes Index
 * Aggregates all application routes
 */

import InteractionController from '../controllers/interaction.controller.js';
import revocationRoutes from './revocation.routes.js';

export function setupRoutes(app, oidc) {
  // Register interaction routes directly on app (before oidc.callback())
  app.get('/interaction/:uid', (req, res) => 
    InteractionController.showAuthorization(req, res, oidc)
  );
  
  app.post('/interaction/:uid/callback', (req, res) => 
    InteractionController.handleCallback(req, res, oidc)
  );
  
  app.use('/admin', revocationRoutes);
  
  // routes configured
}

