/**
 * Simple account store for demo purposes
 * In production, this would connect to your user database
 */
const users = new Map([
  ['user1', {
    accountId: 'user1',
    email: 'user1@example.com',
    email_verified: true,
    name: 'John Doe',
    preferred_username: 'johndoe',
    allowOfflineAccess: false, // User1 does not allow offline access
  }],
  ['user2', {
    accountId: 'user2',
    email: 'user2@example.com',
    email_verified: true,
    name: 'Jane Smith',
    preferred_username: 'janesmith',
    allowOfflineAccess: true, // User2 allows offline access
  }],
]);

export class Account {
  constructor(id, attributes) {
    this.accountId = id;
    Object.assign(this, attributes);
  }

  /**
   * @param use - can be "id_token" or "userinfo"
   * @param scope - the intended scope
   */
  async claims(use, scope) {
    const claims = {
      sub: this.accountId,
      email: this.email,
      email_verified: this.email_verified,
    };

    if (scope.includes('profile')) {
      claims.name = this.name;
      claims.preferred_username = this.preferred_username;
    }

    return claims;
  }

  static async findAccount(ctx, id, token) {
    const account = users.get(id);
    if (!account) {
      return undefined;
    }
    return new Account(id, account);
  }

}

