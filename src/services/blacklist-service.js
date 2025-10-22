const blacklist = new Map();

class BlacklistService {
  static async add(tid, expiresIn, metadata = {}) {
    const expiresAt = Date.now() + (expiresIn * 1000);
    
    blacklist.set(tid, {
      tid,
      blacklistedAt: Date.now(),
      expiresAt,
      ...metadata,
    });
    
    setTimeout(() => {
      blacklist.delete(tid);
    }, expiresIn * 1000);
    
    return true;
  }
  
  static async isBlacklisted(tid) {
    if (!tid) return false;
    
    const entry = blacklist.get(tid);
    if (!entry) return false;
    
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      blacklist.delete(tid);
      return false;
    }
    
    return true;
  }
  
  static async remove(tid) {
    const existed = blacklist.has(tid);
    blacklist.delete(tid);
    return existed;
  }
  
  static async getInfo(tid) {
    return blacklist.get(tid);
  }
  
  static async size() {
    return blacklist.size;
  }
  
  static async getAll() {
    return Array.from(blacklist.values());
  }
  
  static async clear() {
    blacklist.clear();
  }
  
  static async addBatch(tokens) {
    const results = [];
    for (const token of tokens) {
      const result = await this.add(token.tid, token.expiresIn, token.metadata);
      results.push({ tid: token.tid, success: result });
    }
    return results;
  }
}

export default BlacklistService;

