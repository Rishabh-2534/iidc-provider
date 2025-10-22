/**
 * Interaction Routes
 * Routes for OAuth authorization flow
 */

import express from 'express';
import InteractionController from '../controllers/interaction.controller.js';

export function createInteractionRoutes(oidc) {
  const router = express.Router();

  // Redirect to client's authorization page
  router.get('/interaction/:uid', (req, res) => {
    return InteractionController.showAuthorization(req, res, oidc);
  });

  // Handle authorization response from client's page
  router.post('/interaction/:uid/callback', (req, res) => {
    return InteractionController.handleCallback(req, res, oidc);
  });

  return router;
}

