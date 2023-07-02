package org.xipki.ca.gateway.acme;

public class AcmeConstants {

  public static final String CMD_directory = "directory";

  public static final String CMD_newNonce = "new-nonce";

  public static final String CMD_newAccount = "new-account";

  // public static final String CMD_newAuthz = "new-authz";

  public static final String CMD_newOrder = "new-order";

  public static final String CMD_order = "order";
  public static final String CMD_orders = "orders";
  public static final String CMD_authz = "authz";
  public static final String CMD_chall = "chall";
  public static final String CMD_revokeCert = "revoke-cert";

  public static final String CMD_keyChange = "key-change";

  public static final String CMD_account= "acct";

  public static final String CMD_cert = "cert";

  public static final String CMD_finalize = "finalize";

  public static final int SC_OK = 200;

  public static final int SC_CREATED = 201;

  public static final int SC_NO_CONTENT = 204;

  public static final int SC_BAD_REQUEST = 400;

  public static final int SC_UNAUTHORIZED = 401;

  public static final int SC_FORBIDDEN = 403;

  public static final int SC_NOT_FOUND = 404;

  public static final int SC_METHOD_NOT_ALLOWED = 405;

  public static final int SC_CONFLICT = 409;

  public static final int SC_INTERNAL_SERVER_ERROR = 500;

  public static final String CT_PROBLEM_JSON = "application/problem+json";

  public static final String CT_JOSE_JSON = "application/jose+json";

  public static final String CT_JSON = "application/json";

  public static final String CT_PEM_CERTIFICATE_CHAIN = "application/pem-certificate-chain";

  public static final String HDR_HOST = "host";

  public static final String HDR_ACCEPT = "accept";

  public static final String HDR_LINK = "Link";

  public static final String HDR_LOCATION = "Location";

  // The Retry-After header is used to ask the client to wait before sending a follow-up
  // HTTP request. It can be a specific time or instead, a delay specified in seconds
  public static final String HDR_RETRY_AFTER = "Retry-After";

  public static final String DNS_01 = "dns-01";

  public static final String HTTP_01 = "http-01";

  public static final String ALPN_01 = "alpn-01";

}
