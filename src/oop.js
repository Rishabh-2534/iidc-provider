const { Buffer } = require('node:buffer');

const cryptoHelper = require("./crypto_helpers");
const reqAuthHelper = require("./req_auth_helper");
const ipRangeCheck = require("ip-range-check");
const constants = require("./constants");
const logger = require("./logger");
const awsHelper = require("./aws_helpers");
const redisHelper = require("./redis_helper");
const { getUserExtIdpStatus } = require("./utils/helper_methods");
const logMsgs = require("./utils/log_messages");
const { handleECGatewayRequest, getOAuthAppInfo } = require("./helpers/ec_gateway_helper");
const { comeenRequestHandler } = require("./helpers/comeen_request_helper");
const { applyFlowConditions, getAppSettingsHandler,  } = require("./helpers/basic_app_config_helper");
const { RESOURCE_FLOWS } = require('./flows');

const key = process.env.ACCOUNT_KEY;
const iv = process.env.ACCOUNT_IV;
const BASE_URL = process.env.BASE_URL;
const EC_API_GATEWAY_BASE_DOMAIN = process.env.EC_API_GATEWAY_BASE_DOMAIN;
const Subdomain_API = process.env.SUBDOMAIN_API;
const Call_subdomain_API = BASE_URL + Subdomain_API;
const GetToken_API = process.env.TOKEN_API;
const Call_Token_API = BASE_URL + GetToken_API;
const GetUserId_API = process.env.GET_USERID_API;
const Call_GetUserId_API = BASE_URL + GetUserId_API;

const resource_permission_api = process.env.RESOURCE_API;
const Call_resource_permission_API = BASE_URL + resource_permission_api;
const redis_key_suffix = process.env.REDIS_TOKEN_KEY_SUFFIX;
const redis_separator = process.env.REDIS_KEY_SEPARATOR;
const jwt_key = process.env.AUTH_KEY;
const odin_jwt_key = process.env.ODIN_AUTH_KEY;
const csrf_check_required = process.env.CSRF_CHECK_REQUIRED;
const IDENTITY_SEGMENT_LIST = process.env.IDENTITY_SEGMENT_LIST;
const IDENTITY_SEGMENT_LIST_API = BASE_URL + IDENTITY_SEGMENT_LIST;
let request_id;

global.client = null;
global.producer = null;

const Bearer = "Bearer ";

exports.handler = async function (event, context, callbackPassed) {
  let tid,
    uid,
    sid,
    flow,
    user_role,
    user_roles,
    user_status,
    userSegmentId,
    userLanguageCode,
    resource_permission,
    resource_authZ_reqd,
    session_key,
    serviceName,
    resource_authN_reqd,
    resource_scope,
    resource_oauth,
    resource_name,
    resource_additional_perm,
    decrypted_token,
    origin_tid,
    idle_timeout,
    ip_range,
    time_range,
    user_timezone,
    context_message,
    ibuid,
    ibsid,
    isei,
    contextObj = {},
    error_code,
    host,
    daid,
    oauth_flag = false,
    cookie_as_token = false,
    oauth_scope,
    token_type,
    token,
    ext_idp,
    domain,
    domain_type,
    ouath_appid,
    sbid,
    oauth_reg_api,
    mid,
    feDomain,
    access_token,
    cookie_flow,
    apiTokenClient,
    isOdinFlow,
    app,
    peopleId,
    orgId,
    user_idp_type,
    authToken = "",
    addOns,
    vaApplicationKey,
    vaApplicationId,
    hasPermissions = [],
    userLanguage,
    userLastName,
    userFirstName,
    isMultiRoleEnabled = constants.yes_flag,
    userLocale,
    forcePwdReset,
    isExternalIdpUser = false,
    appName = "";
    branding = "{}",
    isClientCredsGrantAccessToken = false;

    const contextAdditionalKeys = { userLanguage, userLastName, userFirstName, userLocale };
  // This will allow us to freeze open connections to Redis
  context.callbackWaitsForEmptyEventLoop = false;

  let methodArn = event.methodArn;
  let headers = event.headers;
  let resource = event.requestContext.path;
  let resource_method = event.requestContext.httpMethod;
  let source_ip = event.requestContext.identity.sourceIp;
  let event_time = event.requestContext.requestTime;
  request_id = event.requestContext.requestId;
  let traceId = headers["X-Amzn-Trace-Id"];
  let websocketId = headers["Sec-WebSocket-Key"];
  let csrfId = headers[constants.csrf_header_name];
  const tsid = headers[constants.HEADER_NAMES.TS_ID];
  const reqSegmentId = headers[constants.HEADER_NAMES.SEGMENT_ID];
  let targetSegmentId = reqSegmentId;

  host = event.headers.Host || event.headers.host;

  let cookieNotPresentFlag;

  // Parse the input for the parameter values
    var tmp = event.methodArn.split(":");
    var apiGatewayArnTmp = tmp[5].split("/");
    var awsAccountId = tmp[4];
    var region = tmp[3];
    var restApiId = apiGatewayArnTmp[0];
    var stage = apiGatewayArnTmp[1];
    var method = apiGatewayArnTmp[2];
    var root_resource = "/"; // root resource
    
    if (apiGatewayArnTmp[3]) {
      root_resource += apiGatewayArnTmp[3];
    }

  const entryLog = `resource: ${resource}, resource_method: ${resource_method},\
 source_ip: ${source_ip}, start_event_context_time: ${event_time}, start_time: ${new Date().toISOString()}, host: ${host}, \
 websocketId: ${websocketId}`;
  // logger.log(request_id, `Entering authorizer ${entryLog}`);

  const callback = function (error, ...rest) {
    const policyEffect = rest[0]?.policyDocument?.Statement[0]?.Effect
    const exitLog = `Entry authorizer log: ${entryLog}, Exiting authorizer log: end_time: ${new Date().toISOString()} ,  tid: ${tid}, error: ${error}, policyEffect: ${policyEffect}, authCheckPassed: ${
      policyEffect?.toLowerCase() === "allow"
    }, context: ${rest[0]?.context ? JSON.stringify(rest[0]?.context) : JSON.stringify({})}`;

    logger.log(request_id, JSON.stringify(exitLog));
    logger.debug(request_id, `CallbackPassed getting executed with error - ${error} and rest - ${rest[0]}`);
    callbackPassed(error, ...rest);
    logger.debug(request_id, `CallbackPassed executed Successfully`);
  }


  var authResponse = {};

  try {
    logger.debug(request_id, 'Request Authorizer Event', JSON.stringify(event));
    logger.debug(request_id, 'Request Authorizer Context', JSON.stringify(context));
    for (const flow of RESOURCE_FLOWS) {
      if (flow.canExecute(event)) {
        return flow.execute(event, callbackPassed, entryLog);
      }
    }

    // validate x-smtip headers
    const validateHeadersRes = validateHeaders(headers);

    if (!validateHeadersRes.areValid) {
      logger.log(
        request_id,
        constants.INVALID_HEADERS,
        JSON.stringify(validateHeadersRes.smtipHeaders)
      );
      // error_code = 2001;
      // context_message = constants.errorCodes[2001];
      // throw constants.INVALID_HEADERS;
    }

    const originHeaderValue = event.headers.origin || event.headers.Origin;
    let origin = originHeaderValue;

    // get tenant id from origin/ host header that is subdomain
    if (host) {
      logger.debug(
        request_id,
        ` if block for get tenant id from origin/ host header that is subdomain line no: 257, time: ${new Date().toISOString()}`,
      );
      domain = host;
      domain_type = "BE";
    } else if (origin && origin.indexOf(redis_separator) > -1) {
      logger.debug(
        request_id,
        ` else block for get tenant id from origin/ host header that is subdomain line no: 264, time: ${new Date().toISOString()}`,
      );
      let url = origin.split(redis_separator);
      origin = url[1].replace("//", "");
      domain = origin;
      domain_type = "FE";
    }
    // logger.log(request_id, "domain " + domain + " domain_type " + domain_type);


    // check if request is for Comeen flow
    const comeenResult = await comeenRequestHandler({
      resource,
      resource_method,
      request_id,
      headers,
    });

    if (comeenResult?.isComeenFlow) {
      logger.debug(
        request_id,
        `comeenResult line no: 285, time: ${new Date().toISOString()}`,
      );
      if (!comeenResult.status) {
        logger.debug(
          request_id,
          ` if not comeenResult line no: 290, time: ${new Date().toISOString()}`,
        );
        callback("Unauthorized");
        return;
      }

      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            null,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        `comeenResult line no: 336, time: ${new Date().toISOString()}`,
      );
      return;
    }    

    const isRequestFromECGateway = domain === EC_API_GATEWAY_BASE_DOMAIN;

    /*
      if request is coming from EC gateway for follwing endpoints
      - /v1/identity/oauth/consent-page
      - /v1/identity/oauth/authorize
      - /v1/identity/oauth/token
      - /v1/account/integrations/ec/callback
      - /v1/account/integrations/ec/oauth2/url
      bypass tenant specific processing and if resource is ec callback/url, bypass auth
    */

    // check if request has the authorize header if yes then token should get validated
    // for eg /v1/identity/oauth/token can have bearer token for renewing the access token
    const auth_header = event.headers["Authorization"] || event.headers["authorization"];

    if (isRequestFromECGateway && (!auth_header || !auth_header.startsWith(Bearer))) {
      logger.debug(
        request_id,
        `isRequestFromECGateway && check for auth_header line no: 360, time: ${new Date().toISOString()}`,
      );
      const isExemptedApiForEC = constants.EC_EXEMPT_APIS_FOR_AUTH.some(
        (exmptApi) =>
          new RegExp(exmptApi).test(resource) &&
          resource_method === constants.http_method.GET
      );
      if (isExemptedApiForEC) {
        logger.debug(
          request_id,
          ` if isRequestFromECGateway line no: 370, time: ${new Date().toISOString()}`,
        );
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              null,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding
            )
          )
        );
        return;
      } else if (constants.EC_OAUTH_RESOURCES.includes(resource)) {
        logger.debug(
          request_id,
          `else isRequestFromECGateway line no: 414, time: ${new Date().toISOString()}`,
        );
          const { success, result } = await handleECGatewayRequest({
            resource,
            queryStringParameters: event.queryStringParameters,
            request_id,
            headers: event.headers,
          });

          if (success) {
            logger.debug(
              request_id,
              `if handleECGatewayRequest line no: 426, time: ${new Date().toISOString()}`,
            );
            tid = result?.account_id;
            // @todo: Do tenant active check here
            callback(
              null,
              generateAllow(
                addToContextObj(
                  contextObj,
                  uid,
                  tid,
                  user_role,
                  methodArn,
                  sid,
                  context_message,
                  error_code,
                  flow,
                  ibuid,
                  ibsid,
                  isei,
                  host,
                  sbid,
                  mid,
                  feDomain,
                  request_id,
                  apiTokenClient,
                  serviceName,
                  app,
                  peopleId,
                  orgId,
                  authToken,
                  null,
                  null,
                  null,
                  null,
                  null,
                  null,
                  targetSegmentId,
                  contextAdditionalKeys,
                  forcePwdReset,
                  isExternalIdpUser,
                  appName,
                  userLanguageCode,
                  branding
                )
              )
            );
            logger.debug(
              request_id,
              `if handleECGatewayRequest line no: 470, time: ${new Date().toISOString()}`,
            );
            return;
          } else {
            error_code = result?.code || 1014;
            context_message = result?.message || constants.errorCodes[1014];
            throw context_message;
          }
      }
    }

    // Skip if gateway API url
    if (
      domain &&
      !isRequestFromECGateway &&
      !websocketId &&
      (!domain.startsWith("api.") || !domain.includes(".simpplr."))
    ) {
      logger.debug(
        request_id,
        `Skip if gateway API url line no: 490, time: ${new Date().toISOString()}`,
      );
      let subdomain_key = [
        constants.domain_key_prefix,
        domain,
        redis_key_suffix,
      ].join(redis_separator);
      // logger.log(request_id, " subdomain_key " + subdomain_key);
      logger.debug(request_id, `Getting tenant details from redis subdomain key line 527: ${subdomain_key}`);
      let tenant = await redisHelper.getKeyPromise(
        subdomain_key
      );
      logger.debug(request_id, `Data Extract from redis is tenantData - ${tenant}`);
      // logger.log(request_id, " after getTenantFromSubdomain " + tenant);
      // in case the domain belongs to sandbox the value will be tid:sbid, else just tid
      if (tenant && tenant.indexOf(redis_separator) > -1) {
        let val = tenant.split(redis_separator);
        tid = val[0];
        sbid = val[1];
      } else {
        tid = tenant;
      }

      // logger.log(request_id, " tenant  " + tid);
      if (!tid) {
        logger.debug(request_id, "Tenant tid not found in Redis, calling API ");
        //make a call and get tenant from subdomain save to Redis
        let tenant, tenant_val;
        try {
          tenant = await reqAuthHelper.getTenantFromSubdomainByAPI(
            Call_subdomain_API,
            domain,
            domain_type,
            request_id
          );
          logger.debug(request_id, `Success: Get tenant data from API at 554`);
          if (tenant) {
            tid = tenant.account_id;
            tenant_val = tid;
            if (tenant.sb_id) {
              sbid = tenant.sb_id;
              tenant_val = tenant_val + redis_separator + sbid;
            }
          } else {
            throw "Tenant not found";
          }
        } catch (error) {
          error_code = 2001;
          context_message = constants.errorCodes[2001];
          throw "Tenant not found";
        }
        // logger.log(
        //   request_id,
        //   " after subdomain API tid " + tid + " sbid " + sbid
        // );
        // logger.log(
        //   request_id,
        //   " subdomain_key added to Redis " + subdomain_key
        // );
        // add the key to Redis
        await redisHelper.setKeyPromise(subdomain_key, tenant_val, null);
      }
      origin_tid = tid;
      logger.debug(
        request_id,
        `Skip if gateway API url line no: 552, time: ${new Date().toISOString()}`,
      );
    }

    let cookie, csrfCookie;

    const loginSamlApiCheck =
      resource &&
      resource.indexOf(constants.saml_api) > -1 &&
      resource_method == constants.http_method.POST;
    
    const loginSsoApiCheck =
      resource &&
      resource.indexOf(constants.sso_login_url_api) > -1 &&
      resource_method == constants.http_method.GET &&
      event.queryStringParameters?.accountId;

    const loginSsoLoginApiCheck =
      resource &&
      resource.indexOf(constants.sso_login_api) > -1 &&
      resource_method == constants.http_method.GET &&
      event.queryStringParameters?.accountId;

    const loginSamlBeAuthorize =
      resource &&
      resource.indexOf(constants.SAML_LOGIN_AUTHORIZE) > -1 &&
      resource_method == constants.http_method.GET;

    const logoutSamlApiCheck =
      resource &&
      resource.indexOf(constants.SAML_LOGOUT_API) > -1 &&
      resource.indexOf(constants.SAML_LOGOUT_REDIRECT_API) === -1 &&
      (resource_method == constants.http_method.POST ||
        resource_method == constants.http_method.GET);

    const logoutOidcApiCheck = resource &&
      resource.indexOf(constants.OIDC_LOGOUT_API) > -1 &&
      resource_method == constants.http_method.GET

    const logoutSamlRedirectApiCheck =
      resource &&
      resource.indexOf(constants.SAML_LOGOUT_REDIRECT_API) > -1 &&
        resource_method == constants.http_method.GET;

    const ignoreCookie =
      resource &&
      constants.IGNORE_COOKIE_RESOURCES.some(
        (path) => resource.indexOf(path) > -1
      ) &&
      resource_method == constants.http_method.POST;

    const mobilePromotionApiCheck =
      resource &&
      resource_method === constants.http_method.GET &&
      constants.mobilePromotionApi.includes(resource);

    if (
      !loginSamlApiCheck &&
      !loginSamlBeAuthorize &&
      !logoutSamlApiCheck &&
      !ignoreCookie &&
      !mobilePromotionApiCheck &&
      !loginSsoApiCheck &&
      !logoutOidcApiCheck && 
      !loginSsoLoginApiCheck
    ) {
      logger.debug(
        request_id,
        ` if !loginSamlApiCheck && !loginSamlBeAuthorize line no: 613, time: ${new Date().toISOString()}`,
      );
      cookie = headers.Cookie || headers.cookie;

      // if (cookie) logger.log(request_id, constants.cookie_is_present);
      // else logger.log(request_id, constants.cookie_not_present);
    }
    // else {
    //   logger.log(request_id, "cookie headers ignored");
    // }

    // if(cookie && cookie.indexOf(constants.semicolon) === -1)
    // If cookie header is populated, and csrf_check_required = 'Y', then both token and csrfid cookies are required
    // Also, csrfid cookie value should match x-smtip-csrfid header value
    if (cookie) {
      logger.debug(
        request_id,
        `If cookie header is populated, validing the cookie if has req prefix`
      );
      let arr, item, tokenCookieFound, csrfCookieFound, errMsg, isCsrfIdMatched = false;
      arr = cookie.split(constants.semicolon);
      for (item of arr) {
        const cookieItem = item.trim();
        if (
          cookieItem.indexOf(constants.cookie_prefix) === 0 
        ) {
          // logger.log(request_id, "found cookie with token= " + item);
          tokenCookieFound = true;
          cookie = cookieItem;
        } else if (cookieItem.indexOf(constants.csrf_cookie_prefix) === 0) {
          // logger.log(request_id, "found cookie with csrfid= " + item);
          csrfCookieFound = true;
          if (!isCsrfIdMatched) {
            csrfCookie = cookieItem;
            isCsrfIdMatched = csrfCookie.substr(constants.csrf_cookie_prefix.length) === csrfId
          }
        }
        if (tokenCookieFound && isCsrfIdMatched) break;
      }

      logger.debug(request_id, `Checking when tokenCookieFound has value - ${tokenCookieFound} & csrf_check_required check has value - ${csrf_check_required}`);
      if (tokenCookieFound && csrf_check_required === constants.yes_flag) {
        // Only if oauth APIs are not called
        logger.debug(request_id, `Start: Check for csrf cookie found`);
        if (resource) {
          let isCsrfExemptResource;
          if (constants.csrf_check_exempt_resources.includes(resource)) {
            isCsrfExemptResource = true;
            // logger.log(
            //   request_id,
            //   "CSRF check: CSRF exempt resource: " + resource
            // );
          }
          if (!isCsrfExemptResource) {
            // logger.log(request_id, "CSRF check: token cookie = " + cookie);
            // logger.log(request_id, "CSRF check: csrf cookie = " + csrfCookie);
            // logger.log(request_id, "CSRF check: csrf header = " + csrfId);

            if (!tokenCookieFound) errMsg = constants.cookie_not_present;
            else if (!csrfCookieFound)
              errMsg = constants.csrf_cookie_not_present;
            else if (!logoutSamlRedirectApiCheck && !csrfId) errMsg = constants.csrf_header_missing;
            else if (
              !logoutSamlRedirectApiCheck && !isCsrfIdMatched
            )
              errMsg = constants.csrf_cookie_header_mismatch;
            if (errMsg) {
              logger.log(request_id, `isCsrfIdMatched: ${!!csrfId} resource: ${resource} headerCsrfId: ${csrfId}, cookieCsrfId: ${csrfCookie.substr(constants.csrf_cookie_prefix.length)} errMsg: ${errMsg}`);
              // logger.log(request_id, {errMsg, tokenCookieFound, csrfCookieFound, });
              error_code = 1006;
              context_message = constants.errorCodes[1006];
              throw errMsg;
            }
            logger.debug(request_id, "CSRF check PASSED !!!");
          }
        }
      }
      logger.debug(
        request_id,
        ` If cookie header is populated and csrf_check_required = 'Y' line no: 790, time: ${new Date().toISOString()}`,
      );
    }

    if (
      resource &&
      resource.indexOf(constants.regToken_api) > -1 &&
      event.queryStringParameters.action == constants.action_param
    ) {
      logger.debug(
        request_id,
        ` If resource.indexOf(constants.regToken_api) > -1 line no: 701, time: ${new Date().toISOString()}`,
      );
      cookie = constants.cookie_prefix + event.queryStringParameters.t;
      cookie_as_token = true;
      // logger.log(request_id, "event.queryStringParameters.t " + cookie);
    }

    //Check if add Ons are required
    let addOnsRequired = false;
    if (resource && new RegExp(constants.VIDEO_APIS).test(resource)) {
      addOnsRequired = true;
    }

    // if token is added as query string decrypt the token
    let query_token = event.queryStringParameters.token,
      query_origin = event.queryStringParameters.origin;

    if (websocketId) {
      logger.debug(
        request_id,
        `Extracting Data from API when websocketId is true`,
      );
      let res_token = await reqAuthHelper.getTokenByAPI(
        Call_Token_API,
        query_token,
        request_id
      );
      access_token = res_token.result.accessToken;
      logger.debug(
        request_id,
        `Success: Retrieving Data from token API when websocket is enabled`,
      );
    }
    // logger.log(
    //   request_id,
    //   "access_token: " + access_token + ", query_origin: " + query_origin
    // );
    if (access_token && !query_origin && websocketId) {
      cookie = "token=" + access_token;
    }
    // if cookie is present
    if (cookie) {
      logger.debug(
        request_id,
        ` if cookie is present line no: 778, with cookie value - ${cookie} && queryOrigin is - ${query_origin}`,
      );
      if (cookie.startsWith(constants.cookie_prefix)) { 
        logger.debug(request_id, `WEB Flow Start, Decrypting Data from Cookie If cookie has token prefix in it.`);
        decrypted_token = JSON.parse(
          cryptoHelper.decrypt(cookie.split(constants.cookie_char)[1], key, iv)
        );
        tid = decrypted_token.tid;
        sid = decrypted_token.sid;
        uid = decrypted_token.uid;
        flow = decrypted_token.flow;
        ibuid = decrypted_token.ibuid;
        ibsid = decrypted_token.ibsid;
        isei = decrypted_token.isei;
        daid = decrypted_token.daid;
        sbid = decrypted_token.sbid;
        // logger.log(
        //   request_id,
        //   "tid " +
        //   tid +
        //   " sid " +
        //   sid +
        //   " uid " +
        //   uid +
        //   " flow " +
        //   flow +
        //   " isei " +
        //   isei +
        //   " daid " +
        //   daid +
        //   " sbid " +
        //   sbid
        // );
        if (!tid || !uid) {
          logger.debug(request_id, `TID - ${tid} OR UID - ${uid} Not found in cookie decryption process`);
          error_code = 1006;
          context_message = constants.errorCodes[1006];
          throw constants.cookie_invalid;
        }
        cookie_flow = true;
        logger.debug(
          request_id,
          `All Required headers decrypting from cookie with cookie_flow - ${cookie_flow} with UserId - ${uid}.`,
        );
      } else {
        logger.debug(
          request_id,
          `Cookie Doesn't Start with token, not a web flow.`,
        );
        cookieNotPresentFlag = true;
        logger.log(request_id, constants.token_absent);
      }
    } else {
      cookieNotPresentFlag = true;
      logger.log(request_id, constants.cookie_not_present);
      //throw(cookie_not_present);
    }
    logger.debug(request_id, `Cookie Flag Value After all execution - ${cookieNotPresentFlag}`);

    if (
      resource &&
      ((resource.indexOf(constants.download_verifyToken) > -1 &&
        resource_method == constants.http_method.POST) ||
        (resource.indexOf(constants.identity_verify_auth_token) > -1 &&
          resource_method == constants.http_method.POST) ||
        (resource.indexOf(constants.oauth_mobile_callback) > -1 &&
          resource_method == constants.http_method.GET) ||
        (resource.indexOf(constants.oauth_client_token) > -1 &&
          resource_method == constants.http_method.POST))
    ) {
      logger.debug(
        request_id,
        ` if resource download_verifyToken && identity_verify_auth_token line no: 815, time: ${new Date().toISOString()}`,
      );
      //for external idp saml no check required
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        ` if resource download_verifyToken && identity_verify_auth_token line no: 858, time: ${new Date().toISOString()}`,
      );
      return;
    }

    logger.debug(request_id, `------- Checking for authZ Token Flow -------`);
    // if authorizer header is added, get tenant id
    let authz_token = event.headers["Authorization"] || event.headers["authorization"];
    if (
      authz_token == undefined &&
      resource &&
      new RegExp(constants.serviceCallbackAllowApi, "i").test(resource)
    ) {
      logger.debug(request_id, `When authToken is undefined, Adding bearer and token from params`);
      authz_token = constants.Bearer + event.queryStringParameters.token;
    }


    // if request from ws gateway to make or disconnect ws connection
    if (
      !authz_token &&
      access_token &&
      query_origin == constants.qp_values.MOBILE &&
      websocketId
    ) {
      authz_token = constants.Bearer + access_token;
    }
    if (authz_token && authz_token.startsWith(Bearer)) {
      logger.debug(
        request_id,
        `---- Bearer Token Flow Started line no: 928, time: ${new Date().toISOString()}`,
      );
      // Chech if authorization header is jwt token
      try {
        logger.debug(request_id, "Start:Decode authToken for Odin Flow");
        token = await reqAuthHelper.decodeAuthToken(authz_token);
        isOdinFlow =
        token &&
        token.aud === constants.AUDIENCE.ODIN &&
        token.iss === constants.TOKEN_ISSUER.ODIN;
        logger.debug(request_id, `End:Decode authToken for Odin Flow - ${isOdinFlow}`);
        if (isOdinFlow) {
          app = constants.APP.ODIN;
          token = await reqAuthHelper.validateAuthToken(
            authz_token,
            odin_jwt_key,
            constants.ODIN_DECODE_ALGORITHM
          );
        } else {
          token = await reqAuthHelper.validateAuthToken(
            authz_token,
            jwt_key,
            constants.DECODE_ALGORITHM
          );
        }
        logger.debug(request_id, `Success: Validating the Auth token at line 953`);
      } catch (err) {
        //log error
        isOdinFlow = false;
        token = false;
        logger.log(request_id, "AuthToken Invalid :--> ", err);
      }
      if (isOdinFlow && token.claims) {
        logger.debug(request_id, `Extracting required headers when isOdinFlow is true and token has claims line - 961`);
        (tid = token.claims.orgUuid), (uid = token.claims.peopleUuid);
        token_type = token.claims.typ;
        user_role =
          token.claims.isUserAppModerator &&
            token.claims.isUserAppModerator === "true"
            ? constants.ACCOUNT_ROLE_ID.APPLICATION_MANAGER
            : constants.ACCOUNT_ROLE_ID.END_USER;
        sbid = token.claims.sbid;
        peopleId = token.peopleId;
        orgId = token.orgId;
      } else if (token) {
        logger.debug(request_id, "authz_token is a valid Bearer JWT");
        if (token.aud) {
          serviceName = token.aud;
          tid = token.tid;
          let serveCallback = false;
          switch (serviceName) {
            case constants.services.NEWSLETTER:
            case constants.services.ODIN:
            case constants.services.VIRTUAL_ASSISTANT:
            case constants.services.ANALYTICS_PROCESSOR: 
            case constants.services.NOTIFICATION: {
              app =
                serviceName === constants.services.ODIN
                  ? constants.APP.ODIN
                  : constants.APP.ZEUS;
              serveCallback = constants.serviceApiMapper[serviceName].some(
                (allowedRoute) => new RegExp(allowedRoute).test(resource)
              );
              break;
            }
            default:
              break;
          }
          logger.debug(
            `Received servicename: ${serviceName}. Route match found status: ${serveCallback}`
          );
          if (serveCallback) {
            callback(
              null,
              generateAllow(
                addToContextObj(
                  contextObj,
                  uid,
                  tid,
                  user_role,
                  methodArn,
                  sid,
                  context_message,
                  error_code,
                  flow,
                  ibuid,
                  ibsid,
                  isei,
                  host,
                  sbid,
                  mid,
                  feDomain,
                  request_id,
                  apiTokenClient,
                  serviceName,
                  app,
                  peopleId,
                  orgId,
                  authToken,
                  hasPermissions,
                  userSegmentId,
                  vaApplicationKey,
                  null,
                  null,
                  null,
                  targetSegmentId,
                  contextAdditionalKeys,
                  forcePwdReset,
                  isExternalIdpUser,
                  appName,
                  userLanguageCode,
                  branding
                )
              )
            );
            return;
          }
        }

        tid = token.tid;
        uid = token.sub;
        mid = token.mid;
        if (token.apiTokenClient) {
          apiTokenClient = token.apiTokenClient;
        } else {
          oauth_scope = token.scope;
          oauth_flag = true;
          ouath_appid = token.aud;
          // This would be the case for access tokens issued
          // via client creds grant flow
          if (token.typ === constants.access_token_type && token.sub === token.client_id) {
            isClientCredsGrantAccessToken = true;
            uid = null;
          }
        }
        token_type = token.typ;
        sbid = token.sbid;

        // logger.log(
        //   request_id,
        //   "@@token user id " +
        //   uid +
        //   " ouath_appid " +
        //   ouath_appid +
        //   " tenant id " +
        //   tid +
        //   " oauth_scope " +
        //   oauth_scope +
        //   " token_type " +
        //   token_type +
        //   " sbid " +
        //   sbid +
        //   " mid " +
        //   mid +
        //   " apiTokenClient " +
        //   apiTokenClient
        // );
        logger.debug(request_id, `TenantId and UserId found in Bearer token with value at line 1079, tid - ${tid} & uid - ${uid}`);
      } else if (
        resource &&
        constants.file_ops_authorization_resources.some(
          (fileAuthResource) => resource.indexOf(fileAuthResource) > -1
        ) &&
        resource_method == constants.http_method.POST &&
        authz_token.startsWith(Bearer)
      ) {
        try {
          decrypted_token = undefined;
          decrypted_token = JSON.parse(
            cryptoHelper.decrypt(authz_token.split(Bearer)[1], key, iv)
          );
        } catch (err) {
          logger.log(
            request_id,
            "authz_token is not valid Bearer encrypted token(cookie value)"
          );
        }

        if (decrypted_token) {
          logger.debug(
            request_id,
            "authz_token is a valid Bearer encrypted token(cookie value) at line 1103"
          );
          tid = decrypted_token.tid;
          sid = decrypted_token.sid;
          uid = decrypted_token.uid;
          flow = decrypted_token.flow;
          ibuid = decrypted_token.ibuid;
          ibsid = decrypted_token.ibsid;
          isei = decrypted_token.isei;
          daid = decrypted_token.daid;
          sbid = decrypted_token.sbid;
        }
      }
      // If its neither a vaild JWT or encrypted token, throw error
      if (!token && !decrypted_token) {
        logger.debug(request_id, "authz_token is NOT VALID at line 1118 !!!");
        throw constants.invalid_authz_token;
      }
      logger.debug(
        request_id,
        ` if authz_token start with Bearer line no: 1123, time: ${new Date().toISOString()}`,
      );
    } else if(authz_token && resource &&  resource.indexOf(constants.oauth_token_api) === -1 && !authz_token.startsWith(Bearer)) {
      logger.log(request_id, `Should not reach here! Received authorization header where scheme is not Bearer for resource ${resource} and method ${resource_method}`);
    }

    const generalAppConfigCheck =
      resource &&
      resource_method === constants.http_method.GET &&
      constants.get_general_app_config.includes(resource);

    // if origin and cookie both are present the tenant ids should match else cookie from different domain is attached
    if (tid && origin_tid) {
      logger.debug(request_id, `Checking when tid and originTid is present at line - 1136 with tid - ${tid} & originTid - ${origin_tid}`);
      if (tid != origin_tid) {
        error_code = 1006;
        context_message = constants.errorCodes[1006];
        throw constants.invalid_cookie;
      }
    } else if (!tid) {
      if (
        (generalAppConfigCheck || loginSamlApiCheck || logoutSamlApiCheck || loginSsoApiCheck || loginSsoLoginApiCheck || logoutOidcApiCheck)
        && /^api\..+\.simpplr/.test(host)
      ) {
        tid = event.queryStringParameters.accountId;
      }
      if (!tid) {
        error_code = 2001;
        context_message = constants.errorCodes[2001];
        throw "Account is not valid";
      }
    }
    // logger.log(request_id, " tenant  " + tid);

    // get FE domain to pass to header
    // if host contains .simpplr. then remove -api
    if (host.includes(".simpplr.")) {
      logger.debug(request_id, `Removing -api from host in case of simpplr domain`);
      // In case of simpplr provided domain
      if (host.indexOf("-api.") > -1) {
        // remove -api if present
        feDomain = host.replace("-api.", ".");
      } else feDomain = host;
    } else {
      logger.debug(request_id, `checking host in case of custom domain`);
      // In case of custom domain
      if (origin) {
        // Get parent domain parts for both origin and host Ex. simpplr.com
        const originTokens = origin.split(".").slice(-2),
          hostTokens = host.split(".").slice(-2);
        if (
          originTokens[0] === hostTokens[0] &&
          originTokens[1] === hostTokens[1]
        ) {
          // If parent domain matches, origin is the feDomain
          feDomain = origin.includes("//") ? origin.split("//")[1] : origin;
        }
      }
      // if host starts with api. then remove api. to make feDomain
      if (!feDomain && host.startsWith("api.")) {
        feDomain = host.replace("api.", "");
      }
    }
    // logger.log(request_id, "feDomain: " + feDomain);

    if (resource && resource.startsWith(constants.fs_token_resource)) {
      logger.debug(
        request_id,
        ` if resource startwith fs_token_resource line no: 1191, time: ${new Date().toISOString()}`,
      );
      app = constants.APP.ODIN;
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        ` if resource startwith fs_token_resource line no: 1239, time: ${new Date().toISOString()}`,
      );
      return;
    }

    //For delegated permission, access should be blocked if user is impersonating another user means ibuid header is present
    if (
      resource &&
      resource.indexOf(constants.delegated_access_api) > -1 &&
      ibuid
    ) {
      error_code = 1013;
      context_message = constants.errorCodes[1013];
      throw "User is already impersonating another user";
    }
   // logger.log(request_id, "AuthN check", resource_authN_reqd);
   
    // check the status of tenant from redis key tenantDetails:<tenantID>:<env>
    // for sandbox the key is tenantDetails:<tenantID>:<sbid>:<env>
    let account_details_key;
    if (sbid) {
      account_details_key = [
        constants.account_details_key_prefix,
        tid,
        sbid,
        redis_key_suffix,
      ].join(redis_separator);
    } else {
      account_details_key = [
        constants.account_details_key_prefix,
        tid,
        redis_key_suffix,
      ].join(redis_separator);
    }

    let tenant_status, subdomain, tenantDetails, tenant_state, appSettings, userDetails, allPermissionsCache;
    try {
       ({ tenantDetails, tenantState: tenant_state, appSettings, userDetails, allPermissionsCache } =
      await reqAuthHelper.getTenantAndUserDetails(
        request_id,
        tid,
        sbid,
        uid,
        isRequestFromECGateway,
        addOnsRequired
      ));
    } catch (err) {
      if (
        err.toString().indexOf(constants.ERROR_MSG.USER_NOT_FOUND_BY_API) > -1
      ) {
        error_code = 1009;
        context_message = constants.errorCodes[1009];
        throw constants.ERROR_MSG.USER_NOT_FOUND_BY_API;
      } else if (
        err.toString().indexOf(constants.ERROR_MSG.TENANT_DETAILS_NOT_FOUND) >
        -1
      ) {
        error_code = 2001;
        context_message = constants.errorCodes[2001];
        throw constants.ERROR_MSG.TENANT_DETAILS_NOT_FOUND;
      } else if (
        err.toString().indexOf(constants.ERROR_MSG.FETCHING_TENANT_STATE) > -1
      ) {
        error_code = 2001;
        context_message = constants.errorCodes[2001];
        throw constants.ERROR_MSG.FETCHING_TENANT_STATE;
      }
      logger.log(request_id, "Error at getTenantAndUserDetails call " + err);
      throw err;
    }

    if (tenantDetails) {
      tenant_status = tenantDetails.status;
      idle_timeout = tenantDetails.ttl;
      ip_range = tenantDetails.ip;
      time_range = tenantDetails.time;
      ext_idp = tenantDetails.extidp;
      addOns = tenantDetails.addOns;
      subdomain = tenantDetails.subdomain;
    }

    if (tenant_status != constants.account_status_active) {
      // tenant status is not active hence access denied
      error_code = 1008;
      context_message = constants.errorCodes[1008];
      throw "Tenant status is not active";
    }

    // if request is from the platform gateway, then feDomain should be set
    // to the subdomain of the tenant. 
    if (isRequestFromECGateway && subdomain) {
      feDomain = subdomain;
    }

    if (resource && resource.startsWith(constants.zeus_mobile_app_token)) {
      logger.debug(
        request_id,
        `if resource zeus_mobile_app_token line no: 1392, time: ${new Date().toISOString()}`,
      );
      orgId = tenantDetails[constants.TENANT_DETAILS_HASH_KEYS.SF_ORG_ID];
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            vaApplicationId,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        `if resource zeus_mobile_app_token line no: 1441, time: ${new Date().toISOString()}`,
      );
      return;
    }

    if(resource && resource.startsWith(constants.BASIC_APP_CONFIG)) {
      logger.debug(
        request_id,
        `if resource starts with BASIC_APP_CONFIG line no: 1411, time: ${new Date().toISOString()}`,
      );
      logger.debug(request_id, `basciAppConfig: appSettings: ${JSON.stringify(appSettings || {})}`);
      appName = appSettings?.appName || constants.NA;
      branding = JSON.stringify(appSettings?.branding || {});

      logger.debug(
        request_id,
        `if resource starts with BASIC_APP_CONFIG line no: 1417, time: ${new Date().toISOString()}`,
      );
    }

    // code to check maintenance mode
    const maintenanceAllowedAPIs =
    resource &&
    resource_method === constants.http_method.GET &&
    constants.ALLOWED_MAINTENANCE_GET_RESOURCES.some((api) =>
      resource.includes(api)
    );

    if (
      tenant_state === constants.ACCOUNT_STATE_MAINTENANCE &&
      !maintenanceAllowedAPIs
    ) {
      // tenant state is in maintenance hence access denied
      error_code = constants.MAINTENANCE_MODE_STATUS_CODE;
      context_message =
        constants.errorCodes[constants.MAINTENANCE_MODE_STATUS_CODE];
      throw "Tenant is in maintenance mode";
    }

    if (isRequestFromECGateway && /^\/v1\/b2b\/identity\/users/.test(resource)) {
      if (isClientCredsGrantAccessToken) {
        // FIX: If the token is revoked
        logger.debug(
          request_id,
          `EC b2b handling block, time: ${new Date().toISOString()}`,
        );

        const appInfo = await getOAuthAppInfo({
          clientId: ouath_appid,
          requestId: request_id,
        });

        if (!appInfo.isActive) {
          logger.debug(
            request_id,
            `EC b2b handling block - app not active, time: ${new Date().toISOString()}`,
          );
          callback('Unauthorized');
          return;
        }
        
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              app,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding,
              ouath_appid,
            )
          )
        );
        logger.debug(
          request_id,
          `EC b2b handling block close, time: ${new Date().toISOString()}`,
        );
        return;
      } else {
        logger.debug(
          request_id,
          `EC b2b handling block - access token does not represent an app, time: ${new Date().toISOString()}`,
        );
        callback('Unauthorized');
        return;
      }
    }

  if (
    resource &&
    ((new RegExp(constants.download_saml_events).test(resource) &&
        (resource_method == constants.http_method.GET ||
          resource_method == constants.http_method.POST)))
  ) {
    logger.debug(
      request_id,
      `resource download_saml_events line no: 1453, time: ${new Date().toISOString()}`,
    );
    callback(
      null,
      generateAllow(
        addToContextObj(
          contextObj,
          uid,
          tid,
          user_role,
          methodArn,
          sid,
          context_message,
          error_code,
          flow,
          ibuid,
          ibsid,
          isei,
          host,
          sbid,
          mid,
          feDomain,
          request_id,
          apiTokenClient,
          serviceName,
          app,
          peopleId,
          orgId,
          authToken,
          hasPermissions,
          userSegmentId,
          vaApplicationKey,
          null,
          null,
          null,
          targetSegmentId,
          contextAdditionalKeys,
          forcePwdReset,
          isExternalIdpUser,
          appName,
          userLanguageCode,
          branding
        )
      )
    );
    logger.debug(
      request_id,
      `resource download_saml_events line no: 1495, time: ${new Date().toISOString()}`,
    );
    return;
  }

    if (addOnsRequired && !addOns.includes(constants.ADD_ONS.VIDEO)) {
      // check for add Ons
      error_code = 1003;
      context_message = constants.errorCodes[1002];
      throw "Resource is not allowed for native video";
    }

    // check for IP range
    if (
      ip_range &&
      source_ip &&
      (ip_range.indexOf(".") > -1 || ip_range.indexOf(":") > -1)
    ) {
      // logger.log(
      //   request_id,
      //   "IP check source_ip " + source_ip + " ip_range " + ip_range
      // );
      if (
        !ipRangeCheck(
          source_ip,
          ip_range.split(constants.ip_range_separator)
        ) &&
        resource &&
        !(resource.indexOf(constants.logout_api) > -1)
      ) {
        error_code = 1002;
        context_message = constants.errorCodes[1002];
        throw "Source IP is not in specified range";
      }
    }

    //Exempt Deskless Apis
    const desklessApisCheck =
      resource &&
      ((resource_method === constants.http_method.POST &&
        constants.desklessAllowPostApis.includes(resource)) ||
        (resource_method === constants.http_method.GET &&
          constants.desklessAllowGetApis.includes(resource)));

    const idpLoginApisCheck =
      resource &&
      resource_method === constants.http_method.GET &&
      constants.idpLoginAllowGetApis.includes(resource);


    // for GET :// /identity/accounts/login user status check is not required
    if (
      generalAppConfigCheck ||
      idpLoginApisCheck ||
      loginSamlApiCheck ||
      desklessApisCheck ||
      mobilePromotionApiCheck ||
      loginSamlBeAuthorize ||
      logoutSamlApiCheck ||
      logoutSamlRedirectApiCheck ||
      logoutOidcApiCheck
    ) {
      // logger.log(
      //   request_id,
      //   "Get Login,Get General-app-config and SAML API allowed"
      // );
      logger.debug(
        request_id,
        `Get Login,Get General-app-config and SAML API allowed line no: 1563, time: ${new Date().toISOString()}`,
      );
      // get segment id from redis
      if (generalAppConfigCheck && tid) {
        if (tsid) {
          logger.debug(request_id, `Getting segmentId from redis at line 1653`);
          const tempUserSessionKey = `${constants.REDIS_PREFIX.TEMP_USER_SESSION}:${tid}:${tsid}:${redis_key_suffix}`
          // logger.log(request_id, "tempUserSessionKey " + tempUserSessionKey);
          const tempUserSession = await redisHelper.getKeyPromise(tempUserSessionKey);
          if (tempUserSession) {
            const { userSegmentId: segmentIdFromRedis } = JSON.parse(tempUserSession)
            // logger.log(request_id, "segmentIdFromRedis " + segmentIdFromRedis);
            userSegmentId = segmentIdFromRedis
          }
        } else if (uid) {
          logger.debug(request_id, `Extracting User details from redis hash at line 1663`);
          // get user segment id from redis
          const segmentIdFromRedis =
            userDetails &&
            userDetails[constants.USER_DETAILS_HASH_SEGMENT_ID_KEY];
          if (segmentIdFromRedis) {
            userSegmentId = segmentIdFromRedis;
            // logger.log(request_id, "segmentIdFromRedis " + userSegmentId);
          }
          if (!userDetails) {
            error_code = 1009;
            context_message = constants.errorCodes[1009];
            throw "user not found by API";
          }
        }
        // if reqSegmentId is present, check if it is valid
        if (
          reqSegmentId &&
          (!reqAuthHelper.isUUID(reqSegmentId) ||
            !(
              await reqAuthHelper.getAllSegments(
                request_id,
                tid,
                sbid,
                uid,
                IDENTITY_SEGMENT_LIST_API
              )
            )?.includes(reqSegmentId))
        ) {
          error_code = 2001;
          context_message = constants.errorCodes[2001];
          throw constants.invalid_segment_id;
        }
      }
      //for external idp saml no check required
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        `Get Login,Get General-app-config and SAML API allowed line no: 1683, time: ${new Date().toISOString()}`,
      );
      return;
    }

    // Exempt Odin APIs
    // Do not check user details from redis/db
    // logger.log(request_id, " resource -> ", resource);
    if (isOdinFlow && resource) {
      logger.debug(
        request_id,
        `Exempt Odin APIs line no: 1694, time: ${new Date().toISOString()}`,
      );
      // logger.log(request_id, " isOdinFlow -> ", isOdinFlow);
      if (
        constants.odinAllowApis.some((regexTemplate) =>
          new RegExp(regexTemplate).test(resource)
        )
      ) {
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              app,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding
            )
          )
        );
      } else {
        // logger.log(request_id, "Trying to access forbidden resource", resource);
        // logger.log(request_id, "Allowed resource", constants.odinAllowApis);
        callback("Unauthorized");
      }
      logger.debug(
        request_id,
        `Exempt Odin APIs line no: 1747, time: ${new Date().toISOString()}`,
      );
      return;
    }
    // logger.log(request_id, "not odin flow ");

    // To be done before user and resource permission check
    // if refresh token is added to authz header, allow only specific API allowed
    if (oauth_flag && token_type == constants.refresh_token_type) {
      // allow the api
      logger.debug(
        request_id,
        ` oauth_flag if refresh token is added to authz header, allow only specific API allowed line no: 1759, time: ${new Date().toISOString()}`,
      );
      if (resource && resource.indexOf(constants.oauth_token_api) > -1) {
        // not allowed if user is invalidated
        let oAuthTokenInvalidatedStatus =
          await reqAuthHelper.isTokenInvalidated(
            tid,
            sbid,
            ouath_appid,
            mid,
            redis_key_suffix,
            redis_separator
          );
        // logger.log(
        //   request_id,
        //   "status of oauth key " + oAuthTokenInvalidatedStatus
        // );
        if (oAuthTokenInvalidatedStatus == constants.yes_flag) {
          // logger.log(request_id, "Oauth token is invalidated");
          callback("Unauthorized");
          return;
        }
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              app,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding
            )
          )
        );
        logger.debug(
          request_id,
          ` oauth_flag if refresh token is added to authz header, allow only specific API allowed line no: 1821, time: ${new Date().toISOString()}`,
        );
        return;
      } else {
        // throw 401 error
        throw "Resource not allowed for refresh token in authorization header";
      }
    }

    // To be done before user and resource permission check
    // Validate scim / service callback mid
    if (
      apiTokenClient &&
      mid &&
      resource &&
      (new RegExp(constants.scimAllowApi, "i").test(resource) ||
        new RegExp(constants.serviceCallbackAllowApi, "i").test(resource))
    ) {
      logger.debug(
        request_id,
        ` Validate scim / service callback mid line no: 1841, time: ${new Date().toISOString()}`,
      );
      const apiTokenStatus = await reqAuthHelper.checkApiTokenStatus({
        apiTokenClient,
        redis_key_suffix,
        redis_separator,
        tid,
        sbid,
        mid,
        request_id,
      });
      if (apiTokenStatus) {
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              app,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding
            )
          )
        );
      } else {
        // logger.log(request_id, "Token is invalid", apiTokenClient, mid);
        callback("Unauthorized");
      }
      logger.debug(
        request_id,
        ` Validate scim / service callback mid line no: 1897, time: ${new Date().toISOString()}`,
      );
      return;
    }

    /*
    Check idle timeout for tenant
    Set 24 hrs if NA
     */
    if (
      tenant_status === constants.account_status_active &&
      (!idle_timeout || idle_timeout === constants.NA)
    ) {
      logger.debug(
        request_id,
        ` Check idle timeout for tenant Set 24 hrs if NA line no: 1912, time: ${new Date().toISOString()}`,
      );
      idle_timeout =
        process.env.SESSION_IDLE_TIMEOUT_IN_MINS ||
        constants.SESSION_IDLE_TIMEOUT_IN_MINS;
      await redisHelper.setHashKeyPromise(
        account_details_key,
        constants.TENANT_DETAILS_HASH_KEYS.TTL,
        idle_timeout
      );
      logger.debug(
        request_id,
        ` Check idle timeout for tenant Set 24 hrs if NA line no: 1925, time: ${new Date().toISOString()}`,
      );
    }

    if (sbid) {
      session_key =
        constants.session_key_prefix +
        redis_separator +
        tid +
        redis_separator +
        sbid +
        redis_separator +
        uid +
        redis_separator +
        sid +
        redis_separator +
        redis_key_suffix;
    } else {
      session_key =
        constants.session_key_prefix +
        redis_separator +
        tid +
        redis_separator +
        uid +
        redis_separator +
        sid +
        redis_separator +
        redis_key_suffix;
    }
    // for mock API add the ttl to session key of user
    // To be done before user and resource permission check
    if (
      resource &&
      resource.indexOf(constants.mock_api) > -1 &&
      resource_method == constants.http_method.GET
    ) {
      logger.debug(
        request_id,
        ` for mock API add the ttl to session key of user line no: 1963, time: ${new Date().toISOString()}`,
      );
      let session_status = await redisHelper.getKeyPromise(
        session_key
      );
      // logger.log(
      //   request_id,
      //   " @@mock API is called Setting ttl to session key session_key " +
      //   session_key +
      //   " session_status " +
      //   session_status +
      //   " idle_timeout " +
      //   idle_timeout
      // );
      if (idle_timeout && !(idle_timeout.indexOf("NA") > -1)) {
        if (session_status) {
          await redisHelper.setKeyPromise(
            session_key,
            session_status,
            idle_timeout * 60
          );
          // send event to kafka to update the session key in RDS
          // await reqAuthHelper.addToSessionEvent(
          //   addToSessionEventObj(
          //     constants.event_lastAccessed,
          //     event_time,
          //     tid,
          //     sid,
          //     sbid
          //   ),
          //   tid,
          //   request_id
          // );
        } else {
          await reqAuthHelper.addToSessionEvent(
            addToSessionEventObj(
              constants.event_sessionExpired,
              event_time,
              tid,
              sid,
              sbid
            ),
            tid,
            request_id
          );
        }
      }
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        ` for mock API add the ttl to session key of user line no: 2051, time: ${new Date().toISOString()}`,
      );
      return;
    }

    if (resource) {
      // check if resource has valid permissions
      logger.debug(
        request_id,
        ` check if resource has valid permissions line no: 2060, time: ${new Date().toISOString()}`,
      );
      let resource_permission_hash;
      if (sbid) {
        resource_permission_hash = [
          constants.resource_permission_prefix,
          tid,
          sbid,
          redis_key_suffix,
        ].join(redis_separator);
      } else {
        resource_permission_hash = [
          constants.resource_permission_prefix,
          tid,
          redis_key_suffix,
        ].join(redis_separator);
      }
      let resource_key;
      if (new RegExp(constants.allow_newsletter, "g").test(resource)) {

        resource_key = constants.METHODS.ANY + redis_separator + constants.allow_newsletter;

      } else if (new RegExp(constants.allow_sentiment, "g").test(resource)) {

        resource_key = constants.METHODS.ANY + redis_separator + constants.allow_sentiment;

      } else {
        resource_key = resource_method + redis_separator + resource;
      }

      try {
        if (process.env.OLD_GET_RESOURCE_FLOW === constants.STRING.TRUE) {
          ({
            resource_permission,
            resource_authZ_reqd,
            resource_authN_reqd,
            resource_scope,
            resource_oauth,
            resource_name,
            resource_additional_perm
          } = await reqAuthHelper.getResourceParamsOld({
            resource_permission_hash,
            resource_key,
            redis_separator,
            request_id,
            tid,
            sbid,
            Call_resource_permission_API,
          }));
        } else {
          resource_key = resource_method + redis_separator + resource;
          let resourceKeysToCheck = [resource_key];

          if (new RegExp(constants.allow_newsletter, "g").test(resource)) {
            // Add allow newsletter route
            resourceKeysToCheck.push(
              `${constants.METHODS.ANY}${redis_separator}${constants.allow_newsletter}`
            );
          } else if (new RegExp(constants.allow_sentiment, "g").test(resource)) {
            // Add allow sentiment route
            resourceKeysToCheck.push(
              `${constants.METHODS.ANY}${redis_separator}${constants.allow_sentiment}`
            );
          }
          logger.debug(request_id, `resource: allPermissionsCache resourceKeysToCheck : ${JSON.stringify(resourceKeysToCheck)} time: ${new Date().toISOString()}`);

          // added basic app config permision because: we wanted this to be really fast and so are avoided the permissions cache lookup.
          if (resource?.startsWith(constants.BASIC_APP_CONFIG)) {
            allPermissionsCache = constants.BASIC_APP_CONFIG_PERM;
          } else {
            allPermissionsCache = await reqAuthHelper.getAllPermissionsCache({ tid, request_id });
          }
          
          logger.debug(request_id, `resource: allPermissionsCache time: ${new Date().toISOString()}`);
          for (const resourceKey of resourceKeysToCheck) {
            try {
              ({
                resource_permission,
                resource_authZ_reqd,
                resource_authN_reqd,
                resource_scope,
                resource_oauth,
                resource_name,
                resource_additional_perm
              } = await reqAuthHelper.getResourceParamsNew({
                tid,
                resource_key: resourceKey,
                redis_separator,
                request_id,
                allPermissionsCache
              }));
              // break if match is found
              break;
            } catch (error) {
              logger.log(request_id, `resource not found for ${resourceKey} : ${JSON.stringify(error)}`);
            }
          }
    
          if (!resource_name || !resource_permission) {
            throw "Resource not found";
          }
        }
        logger.debug(
          request_id,
          ` check if resource has valid permissions line no: 2157, time: ${new Date().toISOString()}`,
        );
      } catch (error) {
        logger.log(request_id, `error in getResourceParams ${error}`);
        error_code = 1003;
        context_message = constants.errorCodes[1003];
        throw "Resource not found";
      }
    }

    hasPermissions = [{
      name: resource_name,
      value: 'idk'
    }]

    // set hasPermission to true when  authn_reqd flag from permission record is Y and authz_reqd is N
    if(resource_authN_reqd === constants.yes_flag && resource_authZ_reqd === constants.no_flag){
       hasPermissions[0].value = 'true';
    }
    // Allow authorize APIs without checking for user details.
    if (resource && resource.indexOf(constants.oauth_authz_api) > -1) {
      // get client id / ouath_appid from query param
      ouath_appid = event.queryStringParameters.client_id;
      if (!ouath_appid) {
        error_code = 1014;
        context_message = constants.errorCodes[1014];
        throw "oauth application is not active";
      } else {
        oauth_flag = true;
        oauth_reg_api = true;
      }
    }
    if (oauth_flag) {
      // check if ouath application is active by checking the redis key
      logger.debug(
        request_id,
        ` check if ouath application is active by checking the redis key line no: 2388, time: ${new Date().toISOString()}`,
      );
      let oauth_app_key;
      if (isRequestFromECGateway) {
        // FIX: Use checkIfOAuthAppIsActive instead
        logger.debug(request_id, `Checking for oauth details when isRequestFromECGateway is ${isRequestFromECGateway}`);
        oauth_app_key = [
          constants.oath_app_key_prefix,
          ouath_appid,
          process.env.REDIS_TOKEN_KEY_SUFFIX,
        ].join(process.env.REDIS_KEY_SEPARATOR);

        // logger.log(request_id, "oauth_app_key " + oauth_app_key);
        let oauthAppDetails;
        try {
          oauthAppDetails = JSON.parse(
            await redisHelper.getKeyPromise(oauth_app_key)
          );
          logger.debug(
            request_id,
            ` check if ouath application is active by checking the redis key line no: 2406, time: ${new Date().toISOString()}`,
          );
        } catch (err) {
          // logger.log(request_id, "error in getting redis key " + err.message);
        }

        // logger.log(
        //   request_id,
        //   "status of oauth app " + JSON.stringify(oauthAppDetails)
        // );

        if (oauthAppDetails?.status !== constants.OAUTH_APP_ACTIVE) {
          error_code = 1014;
          context_message = constants.errorCodes[1014];
          throw "oauth application is not active";
        }

        // if tid present in redis check it against tid of token
        if (oauthAppDetails?.tid && oauthAppDetails.tid !== tid) {
          error_code = 1014;
          context_message = constants.errorCodes[1014];
          throw "oauth application is not active";
        }
      } else {
        if (sbid) {
          oauth_app_key = [
            constants.oath_app_key_prefix,
            tid,
            sbid,
            ouath_appid,
            redis_key_suffix,
          ].join(redis_separator);
        } else {
          oauth_app_key = [
            constants.oath_app_key_prefix,
            tid,
            ouath_appid,
            redis_key_suffix,
          ].join(redis_separator);
        }
        // logger.log(request_id, "oauth_app_key " + oauth_app_key);

        oauthAppDetails = await redisHelper.getKeyPromise(oauth_app_key);
        // logger.log(request_id, "status of oauth app " + oauthAppDetails);
        if (oauthAppDetails != constants.User_session_status_active) {
          error_code = 1014;
          context_message = constants.errorCodes[1014];
          throw "oauth application is not active";
        }
      }
    }

    // for oath APIs like /oauth/authorize and /oauth/token user status check is not required
    //if((resource.indexOf(constants.oauth_token_api)>-1 || resource.indexOf(constants.oauth_authz_api)>-1)){
    if (
      oauth_reg_api ||
      (resource && resource.indexOf(constants.oauth_token_api) > -1)
    ) {
      // logger.log(request_id, "/oauth/authorize or /oauth/token allowed");
      logger.debug(
        request_id,
        `if oauth_reg_api /oauth/authorize or /oauth/token allowed line no: 2467, time: ${new Date().toISOString()}`,
      );
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        `if oauth_reg_api /oauth/authorize or /oauth/token allowed line no: 2509, time: ${new Date().toISOString()}`,
      );
      return;
    }
    logger.debug(request_id, `Checking for UID If not Found in Redis OR DB at line 2643`);
    // Start checking for User details from here onwards.
    if (uid == null) {
      logger.debug(request_id, "user id is null before status check - Not Found");
      error_code = 1006;
      context_message = constants.errorCodes[1006];
      throw constants.userid_absent;
    }
    logger.debug(request_id, `UID Found in Redis OR DB at line 2651, Extracting userDetails for deskless or idp route`);
    // Extract all the required user details before checking deskless and external IDP route permissions.
    // verify if user has valid status from hashset userDetails:<tenantID>:<userID>:<env>

      user_role = userDetails[constants.user_details_hash_role_key];
      user_roles = reqAuthHelper.parseAsJsonOrString(userDetails[constants.user_details_hash_roles_key]);
      user_status = userDetails[constants.user_details_hash_status_key];
      user_timezone = userDetails[constants.user_details_hash_timezone_key];
      user_idp_type = userDetails[constants.user_details_hash_idp_type_key];
      userSegmentId = userDetails[constants.USER_DETAILS_HASH_SEGMENT_ID_KEY];
      contextAdditionalKeys.userFirstName = userDetails[constants.USER_DETAILS_HASH_FIRSTNAME_KEY];
      contextAdditionalKeys.userLastName = userDetails[constants.USER_DETAILS_HASH_LASTNAME_KEY];
      contextAdditionalKeys.userLanguage = userDetails[constants.USER_DETAILS_HASH_LANGUAGE_KEY];
      contextAdditionalKeys.userTimezone = userDetails[constants.user_details_hash_timezone_key];
      contextAdditionalKeys.userLocale = userDetails[constants.USER_DETAILS_HASH_LOCALE_KEY];
      userLanguageCode = userDetails[constants.USER_DETAILS_HASH_LANGUAGE_CODE_KEY];
      isMultiRoleEnabled = userDetails[constants.USER_DETAILS_HASH_MULTI_ROLE_ENABLED];
      forcePwdReset = userDetails[constants.USER_DETAILS_HASH_FORCE_PWD_RESET_KEY];

      // logger.log(
      //   request_id,
      //   `user details from redis: status: ${user_status} || role: ${user_role} || timezone: ${user_timezone} || idpType: ${user_idp_type} || segmentId: ${userSegmentId}`
      // );
    // if reqSegmentId is present, check if it is valid
    if (
      reqSegmentId &&
      (!reqAuthHelper.isUUID(reqSegmentId) ||
        !(
          await reqAuthHelper.getAllSegments(
            request_id,
            tid,
            sbid,
            uid,
            IDENTITY_SEGMENT_LIST_API
          )
        )?.includes(reqSegmentId))
    ) {
      logger.debug(
        request_id,
        `if reqSegmentId is present, check if it is valid line no: 2704, time: ${new Date().toISOString()}`,
      );
      error_code = 2001;
      context_message = constants.errorCodes[2001];
      throw constants.invalid_segment_id;
    }

    if (
      reqSegmentId &&
      reqSegmentId !== userSegmentId &&
      user_role !== constants.ACCOUNT_ROLE_ID.APPLICATION_MANAGER
    ) {
      error_code = 1003;
      context_message = constants.errorCodes[1003];
      throw new Error(
        logMsgs.segmentMismatchedMsg(userSegmentId, reqSegmentId)
      );
    }


    const { isOrgExtIdp, isUserExtIdp } = getUserExtIdpStatus(
      ext_idp,
      user_idp_type
    );

    isExternalIdpUser = isUserExtIdp;
    // if external idp is integrated for the account the APIs for login and registration should be blocked
    if (isOrgExtIdp) {
      // allow logout in case of ext idp
      logger.debug(
        request_id,
        `allow logout in case of ext idp line no: 2734, time: ${new Date().toISOString()}`,
      );
      if (resource && resource.indexOf("/logout") > -1) {
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              app,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding
            )
          )
        );
        return;
      }

      if (
        (resource &&
          constants.extidp_global_block_resources.includes(resource)) ||
        (resource &&
          resource.indexOf(constants.regToken_api) > -1 &&
          !(event.queryStringParameters.action == constants.action_param))
      ) {
        error_code = 1003;
        context_message = constants.errorCodes[1003];
        throw "Resource is not allowed for external idp integrated account";
      }

      if (isUserExtIdp) {
        if (
          resource &&
          constants.extidp_user_block_resources.includes(resource) &&
          //This route will be accesible in the case of PURE SSO tenant as well.
          //We do not check tenant IDP options in the authorizer.
          user_role !== constants.ACCOUNT_ROLE_ID.APPLICATION_MANAGER
        ) {
          error_code = 1003;
          context_message = constants.errorCodes[error_code];
          throw "Resource is not allowed for users having external idp integrated.";
        }
      }
      logger.debug(
        request_id,
        `allow logout in case of ext idp line no: 2805, time: ${new Date().toISOString()}`,
      );
    }

    // check for password reset flow
    if (flow == constants.password_reset_flag) {
      logger.debug(
        request_id,
        `check for password reset flow line no: 2813, time: ${new Date().toISOString()}`,
      );
      // logger.log(request_id, "@@@@@@@ inside RESET@@@@@@@@");
      // check the resources and allow them
      for (let res of constants.reset_check_resources) {
        if (resource && resource.indexOf(res) > -1) {
          // logger.log(request_id, "found reset_check_resources " + res);
          callback(
            null,
            generateAllow(
              addToContextObj(
                contextObj,
                uid,
                tid,
                user_role,
                methodArn,
                sid,
                context_message,
                error_code,
                flow,
                ibuid,
                ibsid,
                isei,
                host,
                sbid,
                mid,
                feDomain,
                request_id,
                apiTokenClient,
                serviceName,
                app,
                peopleId,
                orgId,
                authToken,
                hasPermissions,
                userSegmentId,
                vaApplicationKey,
                null,
                null,
                null,
                targetSegmentId,
                contextAdditionalKeys,
                forcePwdReset,
                isExternalIdpUser,
                appName,
                userLanguageCode,
                branding
              )
            )
          );
          return;
        }
      }
      // logger.log(request_id, "Not allowed for Password Reset flow");
      error_code = 1006;
      context_message = constants.errorCodes[1006];
      logger.debug(
        request_id,
        `check for password reset flow line no: 2866, time: ${new Date().toISOString()}`,
      );
      throw "Not allowed for Password Reset flow";
    }

    // check for recover mfa flow
    if (flow == constants.recover_mfa_flag) {
      // logger.log(request_id, "@@@@@@@ inside RECOVER MFA @@@@@@@@");
      // check the resources and allow them
      logger.debug(
        request_id,
        `check for recover mfa flow line no: 2877, time: ${new Date().toISOString()}`,
      );
      for (let res of constants.recover_mfa_check_resources) {
        if (resource && resource.indexOf(res) > -1) {
          // logger.log(request_id, "found recover_mfa_check_resources " + res);
          callback(
            null,
            generateAllow(
              addToContextObj(
                contextObj,
                uid,
                tid,
                user_role,
                methodArn,
                sid,
                context_message,
                error_code,
                flow,
                ibuid,
                ibsid,
                isei,
                host,
                sbid,
                mid,
                feDomain,
                request_id,
                apiTokenClient,
                serviceName,
                app,
                peopleId,
                orgId,
                authToken,
                hasPermissions,
                userSegmentId,
                vaApplicationKey,
                null,
                null,
                null,
                targetSegmentId,
                contextAdditionalKeys,
                forcePwdReset,
                isExternalIdpUser,
                appName,
                userLanguageCode,
                branding
              )
            )
          );
          return;
        }
      }
      // logger.log(request_id, "Not allowed for Recover MFA flow");
      error_code = 1006;
      context_message = constants.errorCodes[1006];
      logger.debug(
        request_id,
        `check for recover mfa flow line no: 2928, time: ${new Date().toISOString()}`,
      );
      throw "Not allowed for Recover MFA flow";
    }

    // check for Force profile update flow
    if (
      flow == constants.forceProfile_update_flag ||
      flow === constants.FORCE_PROFILE_UPDATE_V2
    ) {
      logger.debug(
        request_id,
        `check for Force profile update flow line no: 2940, time: ${new Date().toISOString()}`,
      );
      // logger.log(
      //   request_id,
      //   "@@@@@@@ inside forcedProfile_update_flag @@@@@@@@"
      // );
      // check the resources and allow them
      for (let res of constants.forceProfile_update_resources) {
        if (resource && resource.indexOf(res) > -1) {
          // logger.log(request_id, "found forceProfile_update_resources " + res);
          callback(
            null,
            generateAllow(
              addToContextObj(
                contextObj,
                uid,
                tid,
                user_role,
                methodArn,
                sid,
                context_message,
                error_code,
                flow,
                ibuid,
                ibsid,
                isei,
                host,
                sbid,
                mid,
                feDomain,
                request_id,
                apiTokenClient,
                serviceName,
                app,
                peopleId,
                orgId,
                authToken,
                hasPermissions,
                userSegmentId,
                vaApplicationKey,
                null,
                null,
                null,
                targetSegmentId,
                contextAdditionalKeys,
                forcePwdReset,
                isExternalIdpUser,
                appName,
                userLanguageCode,
                branding
              )
            )
          );
          return;
        }
      }
      // logger.log(request_id, "Not allowed for ForceProfile update flow");
      error_code = 1006;
      context_message = constants.errorCodes[1006];
      logger.debug(
        request_id,
        `check for Force profile update flow line no: 2996, time: ${new Date().toISOString()}`,
      );
      throw "Not allowed for ForceProfile update flow";
    }

    // check for Force pwd reset update flow
    if (flow == constants.pwdPolicy_reset_flag) {
      // logger.log(request_id, "@@@@@@@ inside pwdPolicy_reset_flag @@@@@@@@");
      // check the resources and allow them
      logger.debug(
        request_id,
        `check for Force pwd reset update flow line no: 3007, time: ${new Date().toISOString()}`,
      );
      for (let res of constants.pwdPolicy_reset_resources) {
        if (resource && resource.indexOf(res) > -1) {
          // logger.log(request_id, "found pwdPolicy_reset_resources " + res);
          callback(
            null,
            generateAllow(
              addToContextObj(
                contextObj,
                uid,
                tid,
                user_role,
                methodArn,
                sid,
                context_message,
                error_code,
                flow,
                ibuid,
                ibsid,
                isei,
                host,
                sbid,
                mid,
                feDomain,
                request_id,
                apiTokenClient,
                serviceName,
                app,
                peopleId,
                orgId,
                authToken,
                hasPermissions,
                userSegmentId,
                vaApplicationKey,
                null,
                null,
                null,
                targetSegmentId,
                contextAdditionalKeys,
                forcePwdReset,
                isExternalIdpUser,
                appName,
                userLanguageCode,
                branding
              )
            )
          );
          return;
        }
      }
      // logger.log(request_id, "Not allowed for pwdPolicy reset flow");
      error_code = 1006;
      context_message = constants.errorCodes[1006];
      logger.debug(
        request_id,
        `check for Force pwd reset update flow line no: 3058, time: ${new Date().toISOString()}`,
      );
      throw "Not allowed for pwdPolicy reset flow";
    }

    if (
      user_status == constants.User_status_active &&
      resource &&
      resource.indexOf(constants.recover_mfa_api) > -1
    ) {
      logger.debug(
        request_id,
        `user_status == constants.User_status_active line no: 3070, time: ${new Date().toISOString()}`,
      );
      // logger.log(request_id, "found recover mfa resource ");
      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            null,
            null,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        `user_status == constants.User_status_active line no: 3113, time: ${new Date().toISOString()}`,
      );
      return;
    }

    if (user_status == constants.User_status_completion_pending) {
      // check the resources and allow them
      logger.debug(
        request_id,
        `user_status == constants.User_status_completion_pending line no: 3122, time: ${new Date().toISOString()}`,
      );
      for (let res of constants.registration_check_resources) {
        if (resource.indexOf(res) > -1) {
          // logger.log(request_id, "found registration_check_resources " + res);
          callback(
            null,
            generateAllow(
              addToContextObj(
                contextObj,
                uid,
                tid,
                user_role,
                methodArn,
                sid,
                context_message,
                error_code,
                flow,
                ibuid,
                ibsid,
                isei,
                host,
                sbid,
                mid,
                feDomain,
                request_id,
                apiTokenClient,
                serviceName,
                app,
                peopleId,
                orgId,
                authToken,
                hasPermissions,
                userSegmentId,
                vaApplicationKey,
                null,
                null,
                null,
                targetSegmentId,
                contextAdditionalKeys,
                forcePwdReset,
                isExternalIdpUser,
                appName,
                userLanguageCode,
                branding
              )
            )
          );
          return;
        }
      }
      // logger.log(
      //   request_id,
      //   "Registration resource not matched for status " +
      //   constants.User_status_completion_pending
      // );
      logger.debug(
        request_id,
        `user_status == constants.User_status_completion_pending line no: 3175, time: ${new Date().toISOString()}`,
      );
      throw constants.user_status_reg_pending;
    } else if (user_status !== constants.User_status_active) {
      logger.debug(request_id, "user status is not active at line - 3354");
      error_code = 1001;
      context_message = constants.errorCodes[1001];
      throw constants.user_status_inactive;
    }
    // logger.log(request_id, "Role of the user is " + user_role);
    if (!user_role) {
      error_code = 2001;
      context_message = constants.errorCodes[2001];
      throw "Role is not attached to the user";
    }

    //  check for Time range using user's timezone
    // logger.log(
    //   request_id,
    //   " event Time " +
    //   event_time +
    //   " time_range " +
    //   time_range +
    //   " user_timezone " +
    //   user_timezone
    // );
    if (
      time_range &&
      time_range.indexOf(":") > -1 &&
      time_range.indexOf("-") > -1 &&
      user_timezone
    ) {
      let allowed = await reqAuthHelper.validateTimeRange(
        event_time,
        time_range,
        user_timezone,
        constants.dateFormat,
        request_id
      );
      // logger.log(request_id, "after timerange allowed " + allowed);
      if (!allowed && !(resource.indexOf(constants.logout_api) > -1)) {
        error_code = 1004;
        context_message = constants.errorCodes[1004];
        throw " Requested time is not in the range specified ";
      }
    }
    // if authN required then check for the session
    //if ((resource_authN_reqd == constants.yes_flag && !(token)) || (cookie_as_token) ){
    if (
      (resource_authN_reqd == constants.yes_flag && cookie_flow) ||
      cookie_as_token
    ) {
      // for delegated access condition check delegation access id daid key in redis
      // the key is daid:<tenant id>:<user_id>:<delegation access id>:<env>
      logger.debug(
        request_id,
        `if authN required then check for the session line no: 3231, time: ${new Date().toISOString()}`,
      );
      if (isei) {
        let delegate_access_key;
        if (sbid) {
          delegate_access_key = [
            constants.delegate_access_prefix,
            tid,
            sbid,
            uid,
            daid,
            redis_key_suffix,
          ].join(redis_separator);
        } else {
          delegate_access_key = [
            constants.delegate_access_prefix,
            tid,
            uid,
            daid,
            redis_key_suffix,
          ].join(redis_separator);
        }
        // logger.log(request_id, "delegate_access_key " + delegate_access_key);
        let delegation_status = await redisHelper.getKeyPromise(
          delegate_access_key
        );
        // logger.log(
        //   request_id,
        //   "status of delegation_status " + delegation_status
        // );
        if (
          !delegation_status ||
          delegation_status !== constants.User_session_status_active
        ) {
          error_code = 1011;
          context_message = constants.errorCodes[1011];
          throw constants.DELEGATED_KEY_INVALID;
        }
      }
      // check the session of user
      let session_status = await redisHelper.getKeyPromise(
        session_key
      );
      // logger.log(request_id, "status of session: " + session_status);
      if (!session_status) {
        // session does not exist in Redis, send Session Expire event to kafka to update RDS
        await reqAuthHelper.addToSessionEvent(
          addToSessionEventObj(
            constants.event_sessionExpired,
            event_time,
            tid,
            sid,
            sbid
          ),
          tid,
          request_id
        );
      }

      if (session_status == constants.User_session_status_delete) {
        // logger.log(request_id, constants.user_forced_logout);
        error_code = 1010;
        context_message = constants.errorCodes[1010];
        throw constants.user_forced_logout;
      }

      if (session_status !== constants.User_session_status_active) {
        // logger.log(request_id, constants.inactive_session);
        error_code = 1007;
        context_message = constants.errorCodes[1007];
        throw constants.inactive_session;
      }

      // update the ttl of session key
      // logger.log(
      //   request_id,
      //   " Setting ttl to session key session_key " +
      //   session_key +
      //   " session_status " +
      //   session_status +
      //   " idle_timeout " +
      //   idle_timeout
      // );
      await redisHelper.setKeyPromise(
        session_key,
        session_status,
        idle_timeout * 60
      );
      // send event to kafka to update the session key in RDS
      // await reqAuthHelper.addToSessionEvent(
      //   addToSessionEventObj(
      //     constants.event_lastAccessed,
      //     event_time,
      //     tid,
      //     sid,
      //     sbid
      //   ),
      //   tid,
      //   request_id
      // );
      logger.debug(
        request_id,
        `if authN required then check for the session line no: 3335, time: ${new Date().toISOString()}`,
      );
    }

    logger.debug(request_id, `Resource - ${resource}, ---- Checking for va regex ----`);
    if (
      resource &&
      new RegExp(constants.virtual_assistant_token_api).test(resource) &&
      resource_method == constants.http_method.POST
    ) {
      logger.debug(
        request_id,
        `virtual_assistant_token_api line no: 3346 time: ${new Date().toISOString()}`,
      );
      const env = process.env.ENV.toLowerCase();
      const { apiKey, applicationId } =
        await awsHelper.getCredsFromAWSSecretsManager(`${env}/va-app/${tid}`);

      callback(
        null,
        generateAllow(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            apiKey,
            applicationId,
            originHeaderValue,
            null,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      logger.debug(
        request_id,
        `virtual_assistant_token_api line no: 3392, time: ${new Date().toISOString()}`,
      );
      return;
    }

    // if Authorization required then proceed with role permission check
    if (resource_authZ_reqd == "Y" || resource_authZ_reqd == "C") {
      /*  
        will be true when multi roles are present for tenant and multi role ff is enabled
      */
        logger.debug(
          request_id,
          `if Authorization required then proceed with role permission check line no: 3583, time: ${new Date().toISOString()}`,
        );
      let access = true;
      if (isMultiRoleEnabled === constants.no_flag) {
        logger.debug(
          request_id,
          `isMultiRoleEnabled is false, Start checking for old permission details`,
        );
        ({ access, hasPermissions } = await reqAuthHelper.getHasPermissionOld({
          tid,
          sbid,
          user_role,
          resource_name,
          resource_authZ_reqd,
          resource_permission,
          request_id
        }));
        logger.debug(
          request_id,
          `if  isMultiRoleEnabled Authorization required then proceed with role permission check line no: 3602, time: ${new Date().toISOString()}`,
        );
        if (!access) {
          error_code = 1003;
          context_message = constants.errorCodes[1003];
          throw "The role does not have permission to access resource";
        }

      } else {
        logger.debug(
          request_id,
          `else !isMultiRoleEnabled Authorization required then proceed with role permission check line no: 3613, time: ${new Date().toISOString()}`,
        );
        
        /*
         --- Commenting permision id flow it will removed in future
        if( process.env.PERM_ID_CACHE_FLOW === constants.yes_flag){
          ({ access, hasPermissions } = await reqAuthHelper.getHasPermissionPermIdFlow({
            tid,
            sbid,
            user_roles,
            resource_name,
            resource_authZ_reqd,
            resource_additional_perm,
            request_id
          }));
          logger.debug(
            request_id,
            `else Authorization required then proceed with role permission check line no: 3444, time: ${new Date().toISOString()}`,
          );
          if (!access) {
            error_code = 1003;
            context_message = constants.errorCodes[1003];
            throw "The role does not have permission to access resource";
          }
        } else {
         */
          logger.debug(
            request_id,
            `else Authorization required then proceed with role permission check line no: 3454, time: ${new Date().toISOString()}`,
          );
          ({ access, hasPermissions } = await reqAuthHelper.getHasPermissionUserIdFlow({
            tid,
            uid,
            sbid,
            resource_name,
            resource_authZ_reqd,
            resource_additional_perm,
            request_id
          }));
          logger.debug(
            request_id,
            `Success: Fetched permission Data from getHasPermissionUserIdFlow with access - ${access} $ hasPermission - ${hasPermissions}`
          );
          if (!access) {
            error_code = 1003;
            context_message = constants.errorCodes[1003];
            throw "The role does not have permission to access resource";
          }

        // }

      }
    }
    // logger.log(
    //   request_id,
    //   " oauth_flag " +
    //   oauth_flag +
    //   " resource_oauth " +
    //   resource_oauth +
    //   " oauth_scope " +
    //   oauth_scope +
    //   " resource_scope " +
    //   resource_scope
    // );
    logger.debug(request_id, `Resource - ${resource}, ---- Checking for allow_newsletter regex ----`);

    if (
      resource &&
      new RegExp(constants.allow_newsletter, "g").test(resource)
    ) {
      // logger.log(request_id, " allow newsletter ");
      // PS-5499 origin Mobile is requried to let mobile app connect with newsletter
      if (
        !cookieNotPresentFlag ||
        (token && origin === constants.qp_values.MOBILE)
      ) {
        logger.debug(
          request_id,
          `PS-5499 origin Mobile is requried to let mobile app connect with newsletter line no: 3503, time: ${new Date().toISOString()}`,
        );
        const { appId, secret } = await awsHelper.getCredsFromAWSSecretsManager(
          process.env.NEWSLETTER_SECRET
        );
        // logger.log(request_id, " appId " + appId + " secret " + secret);
        const hash = cryptoHelper.createHmacHelper(secret, tid);
        authToken = `${appId}:${hash}`;
        logger.debug(
          request_id,
          `PS-5499 origin Mobile is requried to let mobile app connect with newsletter line no: 3513, time: ${new Date().toISOString()}`,
        );
      } else {
        throw constants.cookie_not_present;
      }
    }
    logger.debug(request_id, `Resource - ${resource}, ---- Checking for allow_sentiment regex ----`);

    if (resource && new RegExp(constants.allow_sentiment, "g").test(resource)) {
      // logger.log(request_id, " allow sentiment ai request");
      // PS-5499 origin Mobile is requried to let mobile app connect with newsletter
      if (
        !cookieNotPresentFlag ||
        (token && origin === constants.qp_values.MOBILE) ||
          resource.indexOf("/v1/attachment/authorize") > -1
      ) {
        logger.debug(
          request_id,
          ` allow sentiment ai request line no: 3530, time: ${new Date().toISOString()}`,
        );
        const { appId, secret } = await awsHelper.getCredsFromAWSSecretsManager(
          process.env.SENTIMENT_SECRET
        );
        // logger.log(request_id, " appId " + appId + " secret " + secret);
        const hash = cryptoHelper.createHmacHelper(secret, tid);
        authToken = `${appId}:${hash}`;
        logger.debug(
          request_id,
          ` allow sentiment ai request line no: 3540, time: ${new Date().toISOString()}`,
        );
      } else {
        throw constants.cookie_not_present;
      }
    }

    if (oauth_flag) {
      if (resource_oauth == "Y") {
        // for mobile check if the user is invalidated by verifying if the redis key for that user exists
        logger.debug(
          request_id,
          ` or mobile check if the user is invalidated by verifying if the redis key for that user exists line no: 3552, time: ${new Date().toISOString()}`,
        );
        if (mid) {
          let oAuthTokenInvalidatedStatus =
            await reqAuthHelper.isTokenInvalidated(
              tid,
              sbid,
              ouath_appid,
              mid,
              redis_key_suffix,
              redis_separator
            );
          // logger.log(
          //   request_id,
          //   "status of oauth key " + oAuthTokenInvalidatedStatus
          // );
          logger.debug(
            request_id,
            ` or mobile check if the user is invalidated by verifying if the redis key for that user exists line no: 3570, time: ${new Date().toISOString()}`,
          );
          if (oAuthTokenInvalidatedStatus == constants.yes_flag) {
            // logger.log(request_id, "Oauth token is invalidated");
            callback("Unauthorized");
            return;
          }
        }
        // verify if scope of resource matches with scope allowed in token
        if (
          !(
            oauth_scope == constants.scope_everything ||
            oauth_scope == resource_scope
          )
        ) {
          // logger.log(
          //   request_id,
          //   "oauth scope for resource does not match with the one in token"
          // );
          error_code = 1003;
          context_message = constants.errorCodes[1003];
          throw "The scope of resource does not match with the ouath scope allowed for user";
        }
      } else if (resource_oauth == "N") {
        // logger.log(
        //   request_id,
        //   "oauth_flag && resource_oauth == N hence not allowed"
        // );
        error_code = 1003;
        context_message = constants.errorCodes[1003];
        throw "The role does not have permission to access resource";
      }
    }
    if(process.env.API_RESPONSE_CACHING && resource && resource.startsWith(constants.BASIC_APP_CONFIG) && userDetails) {
      logger.debug(request_id, `Basic App Config Success- Calling Cache Accelerator`);
      reqAuthHelper.invokeCacheAccelerator({
        tid,
        uid,
        requestId: request_id,
        userSegmentId,
        targetSegmentId,
        host,
        origin,
        feDomain,
      });
      logger.debug(request_id, `Basic App Config Success- Cache Accelerator Call Done`);
    }
  } catch (error) {
    logger.log(request_id, "Reached catch block in request handler: " + error);
    if (error) {
      logger.log(request_id, `Error occured: ${resource} ${error.toString()} ${error?.stack}` );
      if (
        (error.toString().indexOf(constants.user_status_inactive) > -1 ||
          error.toString().indexOf(constants.user_status_reg_pending) > -1) &&
        resource.indexOf(constants.login_api) > -1
      ) {
        logger.log(
          request_id,
          "User status is inactive or reg pending allowing to go to BE for login api"
        );
        callback(
          null,
          generateAllow(
            addToContextObj(
              contextObj,
              uid,
              tid,
              user_role,
              methodArn,
              sid,
              context_message,
              error_code,
              flow,
              ibuid,
              ibsid,
              isei,
              host,
              sbid,
              mid,
              feDomain,
              request_id,
              apiTokenClient,
              serviceName,
              app,
              peopleId,
              orgId,
              authToken,
              hasPermissions,
              userSegmentId,
              vaApplicationKey,
              null,
              null,
              null,
              targetSegmentId,
              contextAdditionalKeys,
              forcePwdReset,
              isExternalIdpUser,
              appName,
              userLanguageCode,
              branding
            )
          )
        );
        return;
      }

    if (error_code && resource?.startsWith(constants.BASIC_APP_CONFIG)) {
      callback("Unauthorized");
      return;
    }

      for (let err of constants.errors) {
        if (error.toString().indexOf(err) > -1) {
          // logger.log(request_id, err);
          callback("Unauthorized");
          return;
        }
      }
      // for random error, log the error message and show generic error code
      if (!error_code) {
        logger.log(request_id, "random Error occured " + error.toString());
        error_code = 2001;
        context_message = constants.errorCodes[2001];
      }
      const statusCode =
        error_code === constants.MAINTENANCE_MODE_STATUS_CODE
          ? constants.SERVICE_UNAVAILABLE_CODE
          : constants.FORBIDDEN_STATUS_CODE;

      await reqAuthHelper.addToAuditLog(
        addToAuditEventObj(
          traceId,
          event_time,
          uid,
          resource_method,
          resource,
          source_ip,
          statusCode,
          error_code,
          context_message,
          request_id,
          websocketId
        ),
        sbid ? tid + ":" + sbid : tid
      );
      callback(
        null,
        generateDeny(
          addToContextObj(
            contextObj,
            uid,
            tid,
            user_role,
            methodArn,
            sid,
            context_message,
            error_code,
            flow,
            ibuid,
            ibsid,
            isei,
            host,
            sbid,
            mid,
            feDomain,
            request_id,
            apiTokenClient,
            serviceName,
            app,
            peopleId,
            orgId,
            authToken,
            hasPermissions,
            userSegmentId,
            vaApplicationKey,
            vaApplicationId,
            null,
            statusCode,
            targetSegmentId,
            contextAdditionalKeys,
            forcePwdReset,
            isExternalIdpUser,
            appName,
            userLanguageCode,
            branding
          )
        )
      );
      return;
    }
  }

  logger.debug(request_id, `Calling final callback at line - 3907`);
  callback(
    null,
    generateAllow(
      addToContextObj(
        contextObj,
        uid,
        tid,
        user_role,
        methodArn,
        sid,
        context_message,
        error_code,
        flow,
        ibuid,
        ibsid,
        isei,
        host,
        sbid,
        mid,
        feDomain,
        request_id,
        apiTokenClient,
        serviceName,
        app,
        peopleId,
        orgId,
        authToken,
        hasPermissions,
        userSegmentId,
        vaApplicationKey,
        null,
        null,
        null,
        targetSegmentId,
        contextAdditionalKeys,
        forcePwdReset,
        isExternalIdpUser,
        appName,
        userLanguageCode,
        branding
      )
    )
  );
};

var addToContextObj = function (
};

var addToSessionEventObj = function (event_name, event_time, tid, sid, sbid) {
};

var addToAuditEventObj = function (
};

var getEventName = function (resource_path, resource_method) {
};

// Help function to generate an IAM policy
//var generatePolicy = function(principalId, tid, user_role,effect, resource, sid, context_message) {
var generatePolicy = function (obj, effect) {
};

var generateAllow = function (obj) {
  return generatePolicy(obj, "Allow");
};

var generateDeny = function (obj) {
  return generatePolicy(obj, "Deny");
};

const validateHeaders = (headers) => {
};