import BlacklistService from '../services/blacklist-service.js';

export async function checkBlacklist(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    
    try {
      const base64Payload = token.split('.')[1];
      if (base64Payload) {
        const payload = JSON.parse(Buffer.from(base64Payload, 'base64').toString());
        
        if (payload.jti) {
          const isBlacklisted = await BlacklistService.isBlacklisted(payload.jti);
          if (isBlacklisted) {
            return res.status(401).json({
              error: 'invalid_token',
              error_description: 'Token has been revoked',
            });
          }
        }
      }
    } catch (error) {
      // Let OIDC provider handle validation
    }
  }
  
  next();
}

