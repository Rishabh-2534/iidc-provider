const storage = new Map();

export function getStorage() {
  return storage;
}
export class NoopAdapter {
  constructor(name) {
    this.name = name;
  }

  async upsert(id, payload, expiresIn) {
    console.log(`🪶 No-op UPSERT for ${this.name} (${id})`);
    // pretend it succeeded
    this.lastPayload = payload;
  }

  async find(id) {
    console.log(`🪶 No-op FIND for ${this.name} (${id})`);
    // simulate an always-valid token if provider re-checks it
    if (this.lastPayload) {
      return this.lastPayload;
    }
    return undefined;
  }

  async destroy(id) {
    console.log(`🪶 No-op DESTROY for ${this.name} (${id})`);
  }

  async consume(id) {
    console.log(`🪶 No-op CONSUME for ${this.name} (${id})`);
  }
}



export class MemoryAdapter {
  constructor(name, tenantId = null) {
    this.name = name;
    this.tenantId = tenantId; // Tenant context for this adapter instance
  }
  
  key(id) {
    // Use 'global' fallback for system-level (non-tenant) records
    const tenantPart = this.tenantId ;
    return `${tenantPart}:${this.name}:${id}`;
  }
  
  sameTenantCheck(data){
    return this.tenantId && data?.tid && data?.tid === this.tenantId;
  }
  async findByUid(uid) {
    // Same as find - JWTs are self-contained
    return this.find(uid);
  }
  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    const expiresAt = expiresIn ? Date.now() + (expiresIn * 1000) : null;
    
    //handel the upsert to the real db based on the key 
    //like if name is accessToken or refreshtoken or grant then different data is stored in table.
    
      console.log(`@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@ ${this.name} UPSERT: `,payload);
    
    storage.set(key, {
      payload,
      expiresAt,
      
    });
    if (this.name === 'Session' && payload.uid) {
      const uidKey = this.key(payload.uid);
      storage.set(uidKey, { payload, expiresAt });
    }
    console.log(`${this.name} UPSERT: ${id} `);
  }

  async find(id) {
    const key = this.key(id);
    const data = storage.get(key);
    //in actual service we will  find in the table 
    if (!data) {
      console.log(`${this.name} FIND: ${id} - NOT FOUND`);
      return undefined;
    }
    
    if (data.expiresAt && Date.now() > data.expiresAt) {
      storage.delete(key);
      console.log(`${this.name} FIND: ${id} - EXPIRED`);
      return undefined;
    }
    
    
    console.log(`${this.name} FIND: ${id} `);
    return data.payload;
  }

  async destroy(id) {
    const key = this.key(id);
    const data = storage.get(key);
    
    
    
    storage.delete(key);
    console.log(`${this.name} DESTROY: ${id} for tenant: ${data?.tid}`);
  }

  async consume(id) {
    const key = this.key(id);
    const data = storage.get(key);
  
    
    if (data && data.payload) {
      data.payload.consumed = Math.floor(Date.now() / 1000);
      console.log(`${this.name} CONSUME: ${id} `);
    }
  }
  async revokeByGrantId(grantId) {
    console.log(`${this.name} revokeByGrantId: Revoking all tokens for grantId: ${grantId} (tenant: ${this.tenantId || 'global'})`);
  
    // Loop through all keys in your storage
    for (const [key, data] of storage.entries()) {
      // Each key looks like "<tenantId>:<modelName>:<id>"
      // Filter by model name and grantId match
      if (
        key.includes(`${this.name}:`) && 
        data?.payload?.grantId === grantId &&
        this.sameTenantCheck(data.payload)
      ) {
        storage.delete(key);
        console.log(`${this.name} revokeByGrantId: Deleted ${key}`);
      }
    }
  }
  

}

