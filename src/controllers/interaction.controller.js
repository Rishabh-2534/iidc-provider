import ClientService from '../services/client.service.js';
import { Account } from '../config/accounts.js';

class InteractionController {
  static async showAuthorization(req, res, oidc) {
    try {
      let interaction;
      try {
        interaction = await oidc.interactionDetails(req, res);
      } catch (err) {
        return res.status(400).send(`
          <!DOCTYPE html>
          <html><body>
            <h1>Session Error</h1>
            <p>Your session has expired. Please <a href="http://localhost:3001">start over</a>.</p>
            <p>Error: ${err.message}</p>
          </body></html>
        `);
      }
      
      const { uid, params, prompt, session } = interaction;
      
      const clientData = await ClientService.getClientDetails(params.client_id);
      // Resolve user display emails from account service to avoid UI/data mismatch
      const u1 = await Account.findAccount(null, 'user1');
      const u2 = await Account.findAccount(null, 'user2');
      
      // Single page: select user and approve/deny in one submit
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Authorization Required</title>
          <style>
            body { 
              font-family: Arial, sans-serif; 
              max-width: 500px; 
              margin: 50px auto; 
              padding: 20px;
              background: #f5f5f5;
            }
            .container {
              background: white;
              padding: 30px;
              border-radius: 8px;
              box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h2 { color: #333; margin-top: 0; }
            .client-info {
              background: #e7f3ff;
              padding: 15px;
              border-radius: 4px;
              margin: 20px 0;
            }
            .scope-list {
              background: #f9f9f9;
              padding: 15px;
              border-radius: 4px;
              margin: 20px 0;
            }
            .user-select {
              margin: 20px 0;
            }
            select, button {
              width: 100%;
              padding: 12px;
              margin: 10px 0;
              border-radius: 4px;
              font-size: 16px;
            }
            select {
              border: 1px solid #ddd;
            }
            .btn-approve {
              background: #28a745;
              color: white;
              border: none;
              cursor: pointer;
              font-weight: bold;
            }
            .btn-approve:hover { background: #218838; }
            .btn-deny {
              background: #dc3545;
              color: white;
              border: none;
              cursor: pointer;
            }
            .btn-deny:hover { background: #c82333; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>🔐 Authorization Required</h2>
            
            <div class="client-info">
              <strong>Application:</strong> ${clientData.client_name || params.client_id}<br>
              <strong>Client ID:</strong> ${params.client_id}
            </div>
            
            <p>This application is requesting access to:</p>
            <div class="scope-list">
              <strong>Permissions:</strong><br>
              ${(params.scope || '').split(' ').map(s => `• ${s}`).join('<br>')}
            </div>
            <form method="POST" action="/interaction/${uid}/callback">
              <div class="user-select">
                <label for="userId"><strong>Select User Account:</strong></label>
                <select id="userId" name="user_id" required>
                  <option value="">-- Choose User --</option>
                  <option value="user1">User 1 (${u1?.email || 'user1@example.com'})</option>
                  <option value="user2">User 2 (${u2?.email || 'user2@example.com'})</option>
                </select>
              </div>
              <button type="submit" name="approved" value="true" class="btn-approve">✅ Approve</button>
              <button type="submit" name="denied" value="true" class="btn-deny">❌ Deny</button>
            </form>
          </div>
        </body>
        </html>
      `);
    } catch (error) {
      return res.status(500).send(`Error processing interaction: ${error.message}`);
    }
  }

  static async handleCallback(req, res, oidc) {
    try {
      const { approved, user_id, denied } = req.body;

      if (denied === 'true') {
        const result = {
          error: 'access_denied',
          error_description: 'User denied authorization',
        };
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
        return;
      }

      if (!user_id) {
        return res.status(400).send('User selection required');
      }

      const interactionDetails = await oidc.interactionDetails(req, res);
      const { params } = interactionDetails;

      const grant = new oidc.Grant({ accountId: user_id, clientId: params.client_id });

      if (params.scope) {
        const scopes = params.scope.split(' ');
        const standardOIDCScopes = ['openid', 'offline_access', 'profile', 'email', 'address', 'phone'];
        const account = await Account.findAccount(null, user_id);
        const isOfflineAllowed = Boolean(account?.allowOfflineAccess);
        const oidcScopes = scopes
          .filter(s => standardOIDCScopes.includes(s))
          .filter(s => s !== 'offline_access' || isOfflineAllowed);
        const resourceScopes = scopes.filter(s => !standardOIDCScopes.includes(s));

        if (oidcScopes.length > 0) grant.addOIDCScope(oidcScopes.join(' '));
        if (resourceScopes.length > 0) grant.addResourceScope('', resourceScopes.join(' '));
      }

      const grantId = await grant.save();

      const result = {
        login: { accountId: user_id, remember: false },
        consent: { grantId },
      };

      await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  }
}

export default InteractionController;
