import express from 'express';
import RevocationService from '../services/revocation.service.js';

const router = express.Router();

router.post('/revoke/user/:userId', async (req, res) => {
  try {
    const result = await RevocationService.revokeUserTokens(req.params.userId);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/revoke/client/:clientId', async (req, res) => {
  try {
    const result = await RevocationService.revokeClientTokens(req.params.clientId);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/revoke/user/:userId/client/:clientId', async (req, res) => {
  try {
    const result = await RevocationService.revokeUserClientTokens(
      req.params.userId,
      req.params.clientId
    );
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/tokens/user/:userId', async (req, res) => {
  try {
    const tokens = await RevocationService.getActiveTokensForUser(req.params.userId);
    res.json({ userId: req.params.userId, activeTokens: tokens.length, tokens });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/tokens/client/:clientId', async (req, res) => {
  try {
    const tokens = await RevocationService.getActiveTokensForClient(req.params.clientId);
    res.json({ clientId: req.params.clientId, activeTokens: tokens.length, tokens });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/debug/storage', async (req, res) => {
  try {
    const { getStorage } = await import('../config/adapter.js');
    const storage = getStorage();
    
    const data = {
      grants: [],
      accessTokens: [],
      refreshTokens: [],
      authCodes: [],
      interactions: [],
      sessions: [],
      other: []
    };
    
    for (const [key, value] of storage.entries()) {
      const entry = { key, ...value.payload, expiresAt: value.expiresAt };
      
      if (key.startsWith('Grant:')) data.grants.push(entry);
      else if (key.startsWith('AccessToken:')) data.accessTokens.push(entry);
      else if (key.startsWith('RefreshToken:')) data.refreshTokens.push(entry);
      else if (key.startsWith('AuthorizationCode:')) data.authCodes.push(entry);
      else if (key.startsWith('Interaction:')) data.interactions.push(entry);
      else if (key.startsWith('Session:')) data.sessions.push(entry);
      else data.other.push(entry);
    }
    
    res.json({
      totalEntries: storage.size,
      breakdown: {
        grants: data.grants.length,
        accessTokens: data.accessTokens.length,
        refreshTokens: data.refreshTokens.length,
        authCodes: data.authCodes.length,
        interactions: data.interactions.length,
        sessions: data.sessions.length,
        other: data.other.length
      },
      data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;

