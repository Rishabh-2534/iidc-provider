import * as jose from 'jose';
//import { demoPublicKeyPEM } from './demo-keys.js';
import { errors } from 'oidc-provider';

export default async function jwtBearerHandler(ctx, next) {
  const { assertion, scope } = ctx.oidc.params;
  const client = ctx.oidc.client;
  const provider = ctx.oidc.provider;

  if (!assertion) throw new errors.InvalidRequest('missing assertion parameter');
  /*
  // ✅ Verify JWT using demo public key
  let payload;
  try {
    const publicKey = await jose.importSPKI(demoPublicKeyPEM, 'RS256');
    const { payload: verified } = await jose.jwtVerify(assertion, publicKey, {
      audience: `${provider.issuer}/token`,
      issuer: client.clientId,
    });
    payload = verified;
  } catch (err) {
    console.error('❌ JWT verification failed:', err);
    throw new errors.InvalidGrant('invalid JWT assertion');
  }
*/
  // Issue Access Token
  const AccessToken = provider.AccessToken;
  const token = new AccessToken({
    accountId: "tenant a",
    client,
    grantId: 'jgfkufyuk',//provider.uuid(),
    scope: 'User:Read',
    resource: 'urn:api',
    format: 'jwt',
  audience: 'urn:api',

  });

  const result=await token.save();
  console.log('result', result);
console.log('token', token);
  ctx.body = {
    access_token: result,
    token_type: 'Bearer',
    expires_in: token.expiration - Math.floor(Date.now() / 1000),
  };

  await next();
}
