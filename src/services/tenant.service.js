export default class TenantService {
  static getHeaderTenantIdFromExpress(req) {
    return (
      req?.headers?.['x-tenant-id'] ||
      req?.headers?.['x-smtip-tid'] ||
      null
    );
  }

  static getHeaderTenantIdFromKoa(ctx) {
    try {
      return (
        ctx?.get?.('x-tenant-id') ||
        ctx?.get?.('x-smtip-tid') ||
        null
      );
    } catch (_) {
      return null;
    }
  }

  static getDefaultTenantId() {
    return process.env.DEFAULT_TENANT_ID || null;
  }

  static getDefaultAccountId() {
    return process.env.DEFAULT_ACCOUNT_ID || null;
  }

  static resolveTenantIdFromExpress(req) {
    return this.getHeaderTenantIdFromExpress(req) || this.getDefaultTenantId();
  }

  static resolveTenantIdFromKoa(ctx) {
    return this.getHeaderTenantIdFromKoa(ctx) || this.getDefaultTenantId();
  }
}



