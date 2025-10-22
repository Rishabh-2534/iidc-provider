import { getStorage } from '../config/adapter.js';
import BlacklistService from './blacklist-service.js';

class RevocationService {
  static async revokeUserTokens(userId) {
    const tokensBlacklisted = await this._blacklistTokensForUser(userId);
    return {
      success: true,
      userId,
      tokensBlacklisted,
      message: `Blacklisted ${tokensBlacklisted} JWT token(s) for user ${userId}`,
    };
  }

  static async revokeClientTokens(clientId) {
    const tokensBlacklisted = await this._blacklistTokensForClient(clientId);
    return {
      success: true,
      clientId,
      tokensBlacklisted,
      message: `Blacklisted ${tokensBlacklisted} JWT token(s) for client ${clientId}`,
    };
  }

  static async revokeUserClientTokens(userId, clientId) {
    const tokensBlacklisted = await this._blacklistTokensForUserAndClient(userId, clientId);
    return {
      success: true,
      userId,
      clientId,
      tokensBlacklisted,
      message: `Blacklisted ${tokensBlacklisted} JWT token(s) for user ${userId} and client ${clientId}`,
    };
  }

  static async _blacklistTokensForUser(userId) {
    const storage = getStorage();
    const tokensBlacklisted = [];
    
    for (const [key, data] of storage.entries()) {
      const payload = data.payload;
      if ((key.startsWith('AccessToken:') || key.startsWith('RefreshToken:')) &&
          payload?.accountId === userId && payload?.jti) {
        const expiresIn = data.expiresAt 
          ? Math.max(0, Math.floor((data.expiresAt - Date.now()) / 1000))
          : 3600;
        
        await BlacklistService.add(payload.jti, expiresIn, {
          userId,
          clientId: payload.clientId,
          reason: 'user_revocation',
        });
        tokensBlacklisted.push(payload.jti);
      }
    }
    return tokensBlacklisted.length;
  }

  static async _blacklistTokensForClient(clientId) {
    const storage = getStorage();
    const tokensBlacklisted = [];
    
    for (const [key, data] of storage.entries()) {
      const payload = data.payload;
      if ((key.startsWith('AccessToken:') || key.startsWith('RefreshToken:')) &&
          payload?.clientId === clientId && payload?.jti) {
        const expiresIn = data.expiresAt 
          ? Math.max(0, Math.floor((data.expiresAt - Date.now()) / 1000))
          : 3600;
        
        await BlacklistService.add(payload.jti, expiresIn, {
          clientId,
          userId: payload.accountId,
          reason: 'client_revocation',
        });
        tokensBlacklisted.push(payload.jti);
      }
    }
    return tokensBlacklisted.length;
  }

  static async _blacklistTokensForUserAndClient(userId, clientId) {
    const storage = getStorage();
    const tokensBlacklisted = [];
    
    for (const [key, data] of storage.entries()) {
      const payload = data.payload;
      if ((key.startsWith('AccessToken:') || key.startsWith('RefreshToken:')) &&
          payload?.accountId === userId &&
          payload?.clientId === clientId && 
          payload?.jti) {
        const expiresIn = data.expiresAt 
          ? Math.max(0, Math.floor((data.expiresAt - Date.now()) / 1000))
          : 3600;
        
        await BlacklistService.add(payload.jti, expiresIn, {
          userId,
          clientId,
          reason: 'user_client_revocation',
        });
        tokensBlacklisted.push(payload.jti);
      }
    }
    return tokensBlacklisted.length;
  }

  static async getActiveTokensForUser(userId) {
    const storage = getStorage();
    const tokens = [];
    
    for (const [key, data] of storage.entries()) {
      const payload = data.payload;
      if ((key.startsWith('AccessToken:') || key.startsWith('RefreshToken:')) &&
          payload?.accountId === userId) {
        
        const isBlacklisted = payload.jti ? await BlacklistService.isBlacklisted(payload.jti) : false;
        
        if (!isBlacklisted) {
          tokens.push({
            type: key.split(':')[0],
            clientId: payload.clientId,
            grantId: payload.grantId,
            expiresAt: data.expiresAt ? new Date(data.expiresAt).toISOString() : null,
            scope: payload.scope,
          });
        }
      }
    }
    
    return tokens;
  }

  static async getActiveTokensForClient(clientId) {
    const storage = getStorage();
    const tokens = [];
    
    for (const [key, data] of storage.entries()) {
      const payload = data.payload;
      if ((key.startsWith('AccessToken:') || key.startsWith('RefreshToken:')) &&
          payload?.clientId === clientId) {
        
        const isBlacklisted = payload.jti ? await BlacklistService.isBlacklisted(payload.jti) : false;
        
        if (!isBlacklisted) {
          tokens.push({
            type: key.split(':')[0],
            userId: payload.accountId,
            grantId: payload.grantId,
            expiresAt: data.expiresAt ? new Date(data.expiresAt).toISOString() : null,
            scope: payload.scope,
          });
        }
      }
    }
    
    return tokens;
  }
}

export default RevocationService;

