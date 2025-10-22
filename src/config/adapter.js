const storage = new Map();

export function getStorage() {
  return storage;
}

export class MemoryAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return `${this.name}:${id}`;
  }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    const expiresAt = expiresIn ? Date.now() + (expiresIn * 1000) : null;
    
    storage.set(key, {
      payload,
      expiresAt,
    });
  }

  async find(id) {
    const key = this.key(id);
    const data = storage.get(key);
    
    if (!data) {
      return undefined;
    }
    
    if (data.expiresAt && Date.now() > data.expiresAt) {
      storage.delete(key);
      return undefined;
    }
    
    return data.payload;
  }

  async findByUid(uid) {
    return this.find(uid);
  }

  async findByUserCode(userCode) {
    for (const [key, data] of storage.entries()) {
      if (data.payload?.userCode === userCode) {
        if (data.expiresAt && Date.now() > data.expiresAt) {
          storage.delete(key);
          return undefined;
        }
        return data.payload;
      }
    }
    return undefined;
  }

  async destroy(id) {
    const key = this.key(id);
    storage.delete(key);
  }

  async consume(id) {
    const key = this.key(id);
    const data = storage.get(key);
    if (data && data.payload) {
      data.payload.consumed = Math.floor(Date.now() / 1000);
    }
  }

  async revokeByGrantId(grantId) {
    for (const [key, data] of storage.entries()) {
      if (data.payload?.grantId === grantId) {
        storage.delete(key);
      }
    }
  }
}

