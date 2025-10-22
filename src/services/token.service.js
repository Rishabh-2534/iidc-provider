const CACHE_TTL = 60000;

const ttlCache = new Map();

class TokenService {
  static cacheClientTTL(clientId, config) {
    if (!config) return;
    
    ttlCache.set(clientId, {
      accessToken: config.authorizationCodeGrant?.accessTokenLifeInSeconds || 3600,
      refreshToken: config.authorizationCodeGrant?.refreshTokenLifeInSeconds || 86400,
      idToken: config.authorizationCodeGrant?.accessTokenLifeInSeconds || 3600,
      authorizationCode: 600,
      clientCredentials: config.clientCredentialsGrant?.accessTokenLifeInSeconds || 3600,
      timestamp: Date.now(),
    });
  }

  static getClientTokenTTL(clientId, tokenType) {
    const cached = ttlCache.get(clientId);
    
    if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
      switch (tokenType) {
        case 'AccessToken':
          return cached.accessToken;
        case 'RefreshToken':
          return cached.refreshToken;
        case 'IdToken':
          return cached.idToken;
        case 'AuthorizationCode':
          return cached.authorizationCode;
        case 'ClientCredentials':
          return cached.clientCredentials;
        default:
          return 3600;
      }
    }
    
    // If not cached, return default
    // Next Client.find() call will cache it
    const defaults = {
      AccessToken: 3600,
      IdToken: 3600,
      RefreshToken: 86400,
      AuthorizationCode: 600,
      ClientCredentials: 3600,
    };
    return defaults[tokenType] || 3600;
  }

  static clearCache() {
    ttlCache.clear();
  }
}

export default TokenService;
