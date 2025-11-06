import { SignJWT, jwtVerify } from 'jose';
import crypto from 'crypto';
import BlacklistService from './services/blacklist-service.js';

export default function createCustomRefreshTokenModel(provider) {
  console.log('🧩 Registering Custom JWT RefreshToken Model');

  const { BaseToken } = provider;

  return class JWTRefreshToken extends BaseToken {
    constructor(...args) {
      super(...args);
      if (!this.iiat) this.iiat = this.iat || Math.floor(Date.now() / 1000);
    }

    static get IN_PAYLOAD() {
      return [...super.IN_PAYLOAD, 'iiat', 'rotations', 'rar'];
    }

    async generateTokenId() {
      if (!this.jti) this.jti = crypto.randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const exp = this.exp || (now + 30 * 24 * 60 * 60); // 30 days
      const payload = {
        jti: this.jti,
        kind: 'RefreshToken',
        clientId: this.clientId,
        accountId: this.accountId,
        grantId: this.grantId,
        gty: this.gty,
        iat: now,
        exp,
      };

      const [key] = provider.keystore.all({ use: 'sig' });
      if (!key) throw new Error('No signing key available');

      return await new SignJWT(payload)
        .setProtectedHeader({ alg: key.alg || 'RS256', kid: key.kid })
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(key.keyObject);
    }

    static async find(value) {
      const keys = provider.keystore.all({ use: 'sig' });
      for (const key of keys) {
        try {
          const { payload } = await jwtVerify(value, key.keyObject, {
            algorithms: [key.alg || 'RS256'],
          });

          const isRevoked = await BlacklistService.has(payload.jti);
          if (isRevoked) return undefined;

          return new this(payload);
        } catch (err) {
          continue;
        }
      }
      return undefined;
    }

    async destroy() {
      if (this.jti) {
        const ttl = this.exp - Math.floor(Date.now() / 1000);
        await BlacklistService.add(this.jti, ttl, { kind: 'RefreshToken', clientId: this.clientId });
      }
    }
  };
}
