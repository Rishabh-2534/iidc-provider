import axios from 'axios';

class TenantDomainService {
  static async getSubdomainForTenant(tenantId, sandboxId) {
    const url = 'https://api-be.dev.simpplr.xyz/v1/account/internal/subdomain';
    const params = { account_id: tenantId };
    //if (sandboxId) params.sb_id = sandboxId;
    
    try {
      const resp = await axios.get(url, { 
        params, 
        timeout: 5000,
        headers: {
          'x-smtip-tid': tenantId,
          'x-smtip-cid': `oidc-provider-${Date.now()}`,
          'Content-Type': 'application/json'
        }
      });
      
      const data = resp.data;
      const nameOrHost = typeof data === 'string'
        ? data
        : (data?.subdomain || data?.subdomain_name || data?.host || data?.domain);
      
      if (!nameOrHost) {
        throw new Error('Invalid tenant domain response: missing subdomain information');
      }
      
      return nameOrHost;
      
    } catch (error) {
      console.error(`❌ Failed to resolve tenant domain for ${tenantId}:`, error.message);
      throw new Error(`Failed to resolve tenant domain: ${error.message}`);
    }
  }

  static buildConsentUrl(subdomain, consentToken) {
    return `https://${subdomain}/userconsent?ct=${encodeURIComponent(consentToken)}`;
  }
}

export default TenantDomainService;


