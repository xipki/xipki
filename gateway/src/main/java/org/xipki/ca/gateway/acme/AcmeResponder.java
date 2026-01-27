// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.Pack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.gateway.acme.msg.*;
import org.xipki.ca.gateway.acme.type.AccountStatus;
import org.xipki.ca.gateway.acme.type.AcmeError;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.CertReqMeta;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.sdk.ErrorEntry;
import org.xipki.ca.sdk.RevokeCertsRequest;
import org.xipki.ca.sdk.RevokeCertsResponse;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.ca.sdk.SdkErrorResponseException;
import org.xipki.ca.sdk.X500NameType;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceFactory;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.audit.AuditLevel;
import org.xipki.util.extra.audit.AuditStatus;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.http.HttpConstants;
import org.xipki.util.extra.http.HttpRespContent;
import org.xipki.util.extra.http.HttpResponse;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.ReflectiveUtil;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.misc.StringUtil;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.ca.gateway.acme.AcmeConstants.*;
import static org.xipki.util.codec.Base64.decodeFast;

/**
 * ACME responder.
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class AcmeResponder {

  private static class HttpRespAuditException extends Exception {

    private final int httpStatus;

    private final String auditMessage;

    private final AuditLevel auditLevel;

    private final AuditStatus auditStatus;

    public HttpRespAuditException(
        int httpStatus, String auditMessage,
        AuditLevel auditLevel, AuditStatus auditStatus) {
      this.httpStatus = httpStatus;
      this.auditMessage = Args.notBlank(auditMessage, "auditMessage");
      this.auditLevel = Args.notNull(auditLevel, "auditLevel");
      this.auditStatus = Args.notNull(auditStatus, "auditStatus");
    }

    public int getHttpStatus() {
      return httpStatus;
    }

    public String getAuditMessage() {
      return auditMessage;
    }

    public AuditLevel getAuditLevel() {
      return auditLevel;
    }

    public AuditStatus getAuditStatus() {
      return auditStatus;
    }

  } // class HttpRespAuditException

  private static class StringContainer {
    String text;
  }

  private static final Logger LOG =
      LoggerFactory.getLogger(AcmeResponder.class);

  private static final Map<String, SignAlgo> joseAlgMap = new HashMap<>();

  private final SdkClient sdk;

  private final PopControl popControl;

  private final SecurityFactory securityFactory;

  private final ContactVerifier contactVerifier;

  private final NonceManager nonceManager;

  private static final Set<String> knownCommands;

  private final boolean termsOfServicePresent;
  private final byte[] directoryBytes;

  private final String directoryHeader;

  private final String host;

  private final String host2;

  private final String baseUrl;

  private final String accountPrefix;

  private final List<AcmeProtocolConf.CaProfile> caProfiles;

  private final Set<String> challengeTypes;

  private final SecureRandom rnd;

  private final AcmeRepo repo;

  private final Map<String, byte[][]> cacertsMap = new ConcurrentHashMap<>();

  private final int tokenNumBytes;

  private final AcmeProtocolConf.CleanupOrderConf cleanOrderConf;

  private final ChallengeValidator challengeValidator;

  private final CertEnroller certEnroller;

  private final AtomicLong lastOrdersCleaned = new AtomicLong(0);

  static {
    knownCommands = CollectionUtil.asUnmodifiableSet(
        CMD_directory,  CMD_newNonce,  CMD_newAccount, CMD_newOrder,
        CMD_revokeCert, CMD_keyChange, CMD_account,    CMD_order,
        CMD_orders,     CMD_authz,     CMD_chall,      CMD_finalize,
        CMD_cert);

    // See https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
    // ECDSA using P-256 and SHA-256
    joseAlgMap.put("ES256", SignAlgo.ECDSA_SHA256);
    // ECDSA using P-234 and SHA-384
    joseAlgMap.put("ES384", SignAlgo.ECDSA_SHA384);
    // ECDSA using P-521 and SHA-512
    joseAlgMap.put("ES512", SignAlgo.ECDSA_SHA512);

    // RSASSA-PKCS1-v1_5 using SHA-256
    joseAlgMap.put("RS256", SignAlgo.RSA_SHA256);
    // RSASSA-PKCS1-v1_5 using SHA-384
    joseAlgMap.put("RS384", SignAlgo.RSA_SHA384);
    // RSASSA-PKCS1-v1_5 using SHA-512
    joseAlgMap.put("RS512", SignAlgo.RSA_SHA512);

    // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    joseAlgMap.put("PS256", SignAlgo.RSAPSS_SHA256);
    // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    joseAlgMap.put("PS384", SignAlgo.RSAPSS_SHA384);
    // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    joseAlgMap.put("PS512", SignAlgo.RSAPSS_SHA512);
  }

  public AcmeResponder(SdkClient sdk, SecurityFactory securityFactory,
                       PopControl popControl, AcmeProtocolConf.Acme conf)
      throws InvalidConfException {
    this.sdk = Args.notNull(sdk, "sdk");
    this.popControl = Args.notNull(popControl, "popControl");
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");

    this.baseUrl = Args.notBlank(conf.getBaseUrl(), "baseUrl");
    this.accountPrefix = this.baseUrl + "acct/";

    AcmeProtocolConf.CleanupOrderConf cleanOrder = conf.getCleanupOrder();
    int expiredOrderDays = (cleanOrder == null) ? 365
        : Math.max(10, cleanOrder.getExpiredCertDays());
    int expiredCertDays = (cleanOrder == null) ? 365
        : Math.max(10, cleanOrder.getExpiredOrderDays());
    this.cleanOrderConf = new AcmeProtocolConf.CleanupOrderConf(
        expiredCertDays, expiredOrderDays);

    try {
      URL url = new URL(baseUrl);
      String host0 = url.getHost();
      int port = url.getPort();
      int dfltPort = url.getDefaultPort();

      if (port == -1) {
        this.host  = host0;
        this.host2 = host0 + ":" + dfltPort;
      } else {
        this.host  = host0 + ":" + port;
        this.host2 = (port == dfltPort) ? host0 : host;
      }
    } catch (MalformedURLException e) {
      throw new InvalidConfException("invalid baseUrl '" + baseUrl + "'");
    }

    this.nonceManager = new NonceManager(conf.getNonceNumBytes());
    this.tokenNumBytes = conf.getTokenNumBytes();
    this.directoryHeader = "<" + baseUrl + "directory>;rel=\"index\"";
    this.caProfiles = conf.getCaProfiles();
    if (conf.getChallengeTypes() != null) {
      List<String> types = conf.getChallengeTypes();
      if (!(types.contains(DNS_01) || types.contains(HTTP_01)
          || types.contains(TLS_ALPN_01))) {
        throw new InvalidConfException(
            "invalid challengeTypes '" + types + "'");
      }
      challengeTypes = new HashSet<>(types);
    } else {
      challengeTypes = new HashSet<>(4);
      challengeTypes.add(DNS_01);
      challengeTypes.add(HTTP_01);
      challengeTypes.add(TLS_ALPN_01);
    }
    LOG.info("challenge types: {}", challengeTypes);

    JsonMap json = new JsonMap();
    json.put("newNonce",   baseUrl + CMD_newNonce);
    json.put("newAccount", baseUrl + CMD_newAccount);
    json.put("newOrder",   baseUrl + CMD_newOrder);
    // newAuthz is not supported
    //addJsonField(sb, "newAuthz", baseUrl + CMD_newAuthz);
    json.put("revokeCert", baseUrl + CMD_revokeCert);
    json.put("keyChange",  baseUrl + CMD_keyChange);

    JsonMap meta = new JsonMap();
    json.put("meta", meta);

    if (StringUtil.isNotBlank(conf.getWebsite())) {
      meta.put("website", conf.getWebsite());
    }

    this.termsOfServicePresent =
        StringUtil.isNotBlank(conf.getTermsOfService());
    if (termsOfServicePresent) {
      meta.put("termsOfService", conf.getTermsOfService());
    }

    if (CollectionUtil.isNotEmpty(conf.getCaaIdentities())) {
      meta.putStrings("caaIdentities", conf.getCaaIdentities());
    }

    meta.put("externalAccountRequired", false);

    this.directoryBytes = StringUtil.toUtf8Bytes(JsonBuilder.toJson(json));

    String str = conf.getContactVerifier();
    if (str != null) {
      str = str.trim();
    }

    if (str == null || str.isEmpty()) {
      this.contactVerifier = new ContactVerifier.DfltContactVerifier();
    } else {
      try {
        this.contactVerifier = ReflectiveUtil.newInstance(str);
      } catch (ObjectCreationException ex) {
        throw new InvalidConfException(
            "invalid contactVerifier '" + str + "'", ex);
      }
    }

    rnd = new SecureRandom();

    if (conf.getDbConf() == null) {
      throw new InvalidConfException("dbConf is not specified");
    }

    try {
      FileOrValue fileOrValue = FileOrValue.ofFile(conf.getDbConf());
      DataSourceWrapper dataSource0 =
          new DataSourceFactory().createDataSource("acme-db", fileOrValue);
      repo = new AcmeRepo(new AcmeDataSource(dataSource0), conf.getCacheSize(),
              conf.getSyncDbSeconds());
    } catch (Exception ex) {
      throw new InvalidConfException("could not initialize database", ex);
    }

    this.challengeValidator = new ChallengeValidator(repo);
    this.certEnroller = new CertEnroller(repo, sdk);
  }

  public void start() {
    Thread t = new Thread(challengeValidator);
    t.setName("challengeValidator");
    t.setDaemon(true);
    t.start();

    t = new Thread(certEnroller);
    t.setName("certEnroller");
    t.setDaemon(true);
    t.start();

    repo.start();
  }

  public void close() {
    challengeValidator.close();
    certEnroller.close();
    nonceManager.close();

    repo.close();
  }

  public HttpResponse service(
      XiHttpRequest servletReq, byte[] request, AuditEvent event) {
    StringContainer command = new StringContainer();

    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    AuditLevel auditLevel = AuditLevel.INFO;
    String auditMessage = null;

    HttpResponse resp;
    try {
      try {
        resp = doService(servletReq, request, event, command);
        int sc = resp.getStatusCode();
        if (sc >= 300 || sc < 200) {
          auditStatus = AuditStatus.FAILED;
          auditLevel = AuditLevel.ERROR;
        }
      } catch (HttpRespAuditException ex) {
        auditStatus = ex.getAuditStatus();
        auditLevel = ex.getAuditLevel();
        auditMessage = ex.getAuditMessage();

        return new HttpResponse(ex.getHttpStatus(), null, null, null);
      } catch (AcmeProtocolException ex) {
        auditLevel = AuditLevel.WARN;
        auditStatus = AuditStatus.FAILED;
        auditMessage = ex.getMessage();
        Problem problem = new Problem(ex.getAcmeError().getQualifiedCode(),
            ex.getAcmeDetail(), null);
        return buildProblemResp(ex.getHttpError(), problem);
      } catch (DataAccessException | CodecException | AcmeSystemException ex) {
        LogUtil.error(LOG, ex, null);
        auditLevel = AuditLevel.ERROR;
        auditStatus = AuditStatus.FAILED;
        if (ex instanceof DataAccessException) {
          auditMessage = "database error";
        } else {
          auditMessage = "ACME system exception";
        }
        return new HttpResponse(SC_INTERNAL_SERVER_ERROR, null, null, null);
      }
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      return new HttpResponse(SC_INTERNAL_SERVER_ERROR, null, null, null);
    } finally {
      event.setStatus(auditStatus);
      event.setLevel(auditLevel);
      if (auditMessage != null) {
        event.addEventData(CaAuditConstants.NAME_message, auditMessage);
      }
    }

    if (command.text != null && !"directory".equals(command.text)) {
      String nonce = nonceManager.newNonce();
      resp.putHeader("Replay-Nonce", nonce)
              .putHeader(HDR_LINK, directoryHeader);
    }

    return resp;
  }

  private HttpResponse doService(
      XiHttpRequest servletReq, byte[] request,
      AuditEvent event, StringContainer commandContainer)
      throws HttpRespAuditException, AcmeProtocolException,
      AcmeSystemException, DataAccessException, CodecException {
    String method = servletReq.getMethod();
    String path = (String) servletReq.getAttribute(
                    HttpConstants.ATTR_XIPKI_PATH);

    String[] tokens;
    String hdrHost = servletReq.getHeader(HDR_HOST);
    if (!host.equals(hdrHost) && !host2.equals(hdrHost)) {
      String message = "invalid header host '" + hdrHost + "'";
      LOG.error(message);
      throw new HttpRespAuditException(SC_BAD_REQUEST, message,
          AuditLevel.ERROR, AuditStatus.FAILED);
    }

    if (path.isEmpty()) {
      path = "/";
    }

    // the first char is always '/'
    String coreUri = path.substring("/".length());
    tokens = coreUri.split("/");

    if (tokens.length < 1) {
      String message = "invalid path " + path;
      LOG.error(message);
      throw new HttpRespAuditException(SC_NOT_FOUND,
          message, AuditLevel.ERROR, AuditStatus.FAILED);
    }

    String command = tokens[0].toLowerCase(Locale.ROOT);
    commandContainer.text = command;

    if (StringUtil.isBlank(command)) {
      command = CMD_directory;
    }

    event.addEventType(command);

    if (!knownCommands.contains(command)) {
      String message = "invalid command '" + command + "'";
      LOG.error(message);
      throw new HttpRespAuditException(SC_NOT_FOUND,
          message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    if (CMD_newNonce.equalsIgnoreCase(command)) {
      int sc = "HEAD".equals(method) ? SC_OK
          : "GET" .equals(method) ? SC_NO_CONTENT : 0;
      if (sc == 0) {
        throw new HttpRespAuditException(SC_METHOD_NOT_ALLOWED,
            "HTTP method not allowed: " + method,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      return new HttpResponse(sc, null, null, null)
          .putHeader("Cache-Control", "no-store");
    } else if (CMD_directory.equalsIgnoreCase(command)) {
      if (!"GET".equals(method)) {
        throw new HttpRespAuditException(SC_METHOD_NOT_ALLOWED,
            "HTTP method not allowed: " + method,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      HttpRespContent respContent = HttpRespContent.ofOk(CT_JSON,
          false, directoryBytes);
      return new HttpResponse(SC_OK, respContent.getContentType(), null,
          respContent.isBase64(), respContent.getContent());
    }

    if (!"POST".equals(method)) {
      throw new HttpRespAuditException(SC_METHOD_NOT_ALLOWED,
          "HTTP method not allowed: " + method,
          AuditLevel.INFO, AuditStatus.FAILED);
    }

    String contentType = servletReq.getContentType();
    if (!CT_JOSE_JSON.equals(contentType)) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "invalid Content-Type '" + contentType + "'");
    }

    JoseMessage body = JoseMessage.parse(toJsonMap(request));
    JsonMap protected_= toJsonMap(decodeFast(body.getProtected()));

    String protectedUrl = protected_.getString("url");
    if (protectedUrl == null) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.malformed, "url is not present");
    }

    if (!protectedUrl.equals(baseUrl + path.substring(1))) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "url is not valid: '" + protectedUrl + "'");
    }

    String nonce = protected_.getString("nonce");
    if (nonce == null) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.badNonce, "nonce is not present");
    }

    if (!nonceManager.removeNonce(nonce)) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.badNonce, null);
    }

    final int MASK_JWK = 1; // jwk is allowed
    final int MASK_KID = 2; // kid is allowed

    int verificationKeyRequirement = CMD_newAccount.equals(command) ? MASK_JWK
        : CMD_revokeCert.equals(command) ? MASK_JWK | MASK_KID : MASK_KID;

    Map<String, String> jwk = protected_.getStringMap("jwk");
    String kid = protected_.getString("kid");

    AcmeAccount account = null;
    PublicKey pubKey;

    if (kid != null && jwk != null) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "Both jwk and kid are specified, but exactly one of them is allowed");
    } else if (jwk != null) {
      if ((verificationKeyRequirement & MASK_JWK) == 0) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
            "kid is specified, but jwk is allowed");
      }

      try {
        pubKey = AcmeUtils.jwkPublicKey(jwk);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "jwkPublicKey");
        throw new AcmeProtocolException(SC_BAD_REQUEST,
            AcmeError.badPublicKey, null);
      }
    } else if (kid != null) {
      if ((verificationKeyRequirement & MASK_KID) == 0) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
            "jwk is specified, but only kid is allowed");
      }

      // extract the location
      if (kid.startsWith(accountPrefix)) {
        Long id = toLongId(kid.substring(accountPrefix.length()));
        if (id != null) {
          account = repo.getAccount(id);
        }
      }

      if (account == null) {
        throw new AcmeProtocolException(SC_BAD_REQUEST,
            AcmeError.accountDoesNotExist, null);
      }

      try {
        pubKey = account.getPublicKey();
      } catch (InvalidKeySpecException e) {
        throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR,
            AcmeError.badPublicKey, null);
      }
    } else {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "None of jwk and kid is specified, but one of them is required");
    }

    // pre-check
    if (CMD_account.equals(command)) {
      if (!protectedUrl.equals(kid)) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
            "kid and url do not match");
      }
    }

    // assert the account is valid
    if (account != null) {
      if (account.getStatus() != AccountStatus.valid) {
        throw new AcmeProtocolException(SC_UNAUTHORIZED,
            AcmeError.unauthorized, "account is not valid");
      }
    }

    verifySignature(protected_.getString("alg"), pubKey, body);

    switch (command) {
      case CMD_newAccount: {
        NewAccountPayload reqPayload = NewAccountPayload.parse(toJsonMap(
            decodeFast(body.getPayload())));

        AcmeAccount existingAccount = repo.getAccountForJwk(jwk);
        if (existingAccount != null) {
          return buildSuccJsonResp(SC_OK, existingAccount.toResponse(baseUrl))
              .putHeader(HDR_LOCATION, existingAccount.getLocation(baseUrl));
        }

        Boolean onlyReturnExisting = reqPayload.getOnlyReturnExisting();
        if (onlyReturnExisting != null && onlyReturnExisting) {
          throw new AcmeProtocolException(SC_BAD_REQUEST,
              AcmeError.accountDoesNotExist, null);
        }

        // create a new account
        Boolean b = reqPayload.getTermsOfServiceAgreed();
        boolean tosAgreed = (b != null) ? b : !termsOfServicePresent;

        if (!tosAgreed) {
          throw new AcmeProtocolException(SC_UNAUTHORIZED,
              AcmeError.userActionRequired,
              "terms of service has not been agreed");
        }

        AcmeAccount newAccount = repo.newAcmeAccount();
        List<String> contacts = reqPayload.getContact();
        if (contacts != null && !contacts.isEmpty()) {
          verifyContacts(contacts);
          newAccount.setContact(contacts);
        }
        newAccount.setExternalAccountBinding(
            reqPayload.getExternalAccountBinding());
        if (b != null) {
          newAccount.setTermsOfServiceAgreed(true);
        }

        newAccount.setJwk(jwk);
        newAccount.setStatus(AccountStatus.valid);
        repo.addAccount(newAccount);

        AccountResponse resp = newAccount.toResponse(baseUrl);

        LOG.info("created new account {}", newAccount.idText());
        return buildSuccJsonResp(SC_CREATED, resp)
            .putHeader(HDR_LOCATION, newAccount.getLocation(baseUrl));
      }
      case CMD_keyChange: {
        JoseMessage reqPayload = JoseMessage.parse(
            toJsonMap(decodeFast(body.getPayload())));
        JsonMap innerProtected = toJsonMap(
            decodeFast(reqPayload.getProtected()));

        Map<String, String> newJwk = innerProtected.getStringMap("jwk");
        AcmeAccount accountForNewJwk = repo.getAccountForJwk(newJwk);
        if (accountForNewJwk != null) {
          // jwk not exists.
          return toHttpResponse(HttpRespContent.of(SC_CONFLICT,
              null, null))
              .putHeader(HDR_LOCATION, accountForNewJwk.getLocation(baseUrl));
        }

        // check payload.account, and payload.oldKey
        JsonMap innerPayload = toJsonMap(decodeFast(reqPayload.getPayload()));
        String innerAccount = innerPayload.getString("account");
        if (!innerAccount.equals(kid)) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
              "invalid payload.account");
        }

        Map<String, String> oldKey = innerPayload.getStringMap("oldKey");
        if (!account.hasJwk(oldKey)) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
              "oldKey does not match the account");
        }

        // check inner signature (by the new key)
        PublicKey newPubKey;
        try {
          newPubKey = AcmeUtils.jwkPublicKey(newJwk);
        } catch (InvalidKeySpecException e) {
          LogUtil.error(LOG, e, "jwkPublicKey");
          throw new AcmeProtocolException(SC_BAD_REQUEST,
              AcmeError.badPublicKey, null);
        }

        verifySignature(protected_.getString("alg"), newPubKey, reqPayload);

        account.setJwk(newJwk);

        LOG.info("changed key of account {}", account.idText());
        return buildSuccJsonResp(SC_OK, account.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, account.getLocation(baseUrl));
      }
      case CMD_account: {
        AccountResponse reqPayload = AccountResponse.parse(toJsonMap(
            decodeFast(body.getPayload())));
        AccountStatus status = reqPayload.getStatus();

        if (status == AccountStatus.revoked) {
          throw new AcmeProtocolException(SC_UNAUTHORIZED,
              AcmeError.unauthorized, "status revoked is not allowed");
        }

        if (status == AccountStatus.deactivated) {
          // 7.3.6.  Account Deactivation
          account.setStatus(AccountStatus.deactivated);
        }

        // 7.3.2.  Account Update
        List<String> contacts = reqPayload.getContact();
        if (contacts != null && !contacts.isEmpty()) {
          verifyContacts(contacts);
          account.setContact(contacts);
        }

        LOG.info("updated account {}", account.idText());
        return buildSuccJsonResp(SC_OK, account.toResponse(baseUrl));
      }
      case CMD_revokeCert: {
        RevokeCertPayload reqPayload = RevokeCertPayload.parse(
            toJsonMap(decodeFast(body.getPayload())));
        Integer reasonCode = reqPayload.getReason();
        CrlReason reason;
        try {
          reason = reasonCode == null ? CrlReason.UNSPECIFIED
              : CrlReason.forReasonCode(reasonCode);
        } catch (Exception e) {
          reason = null;
        }

        if (reason == null
            || !CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(reason)) {
          throw new AcmeProtocolException(SC_BAD_REQUEST,
              AcmeError.badRevocationReason,
              "bad revocation reason " + reasonCode);
        }

        byte[] certBytes = decodeFast(reqPayload.getCertificate());

        Certificate cert;
        byte[] encodedIssuer;
        try {
          cert = Certificate.getInstance(certBytes);
          encodedIssuer = cert.getIssuer().getEncoded();
        } catch (Exception e) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
              "malformed certificate");
        }

        LOG.info("try to revoke certificate with (subject={}, issuer={}, " +
                "serialNumber={})",
            cert.getSubject(), cert.getIssuer(), cert.getSerialNumber());

        if (jwk != null) {
          // request is signed with the private paired with the certificate.
          boolean jwkAndCertMatch;
          try {
            jwkAndCertMatch = AcmeUtils.matchKey(jwk,
                cert.getSubjectPublicKeyInfo());
          } catch (InvalidKeySpecException e) {
            LogUtil.error(LOG, e, "matchKey");
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.badPublicKey, "bad jwk");
          }
          if (!jwkAndCertMatch) {
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.unauthorized, "jwk and certificate do not match");
          }
        }

        AcmeOrder order = Optional.ofNullable(
            repo.getOrderForCert(certBytes)).orElseThrow(
                () -> new AcmeProtocolException(
                    SC_BAD_REQUEST, AcmeError.unauthorized,
                    "certificate not enrolled through this ACME server"));

        if (jwk == null) {
          // account is non-null here.
          // request is signed with the account keypair.
          // assert the certificate is owned by the account
          if (order.getAccountId() != account.getId()) {
            // certificate has not been issued to the given account.
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.unauthorized, "account and certificate do not match");
          }
        }

        RevokeCertsRequest.Entry sdkEntry = new RevokeCertsRequest.Entry(
            cert.getSerialNumber().getPositiveValue(), reason, null);

        RevokeCertsRequest sdkReq = new RevokeCertsRequest(null,
            new X500NameType(encodedIssuer), null,
            new RevokeCertsRequest.Entry[]{sdkEntry});

        RevokeCertsResponse sdkResp;
        try {
          sdkResp = sdk.revokeCerts(sdkReq);
          LOG.info("revoked certificate");
        } catch (SdkErrorResponseException e) {
          LogUtil.error(LOG, e, "sdk.revokeCerts");
          throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR,
              AcmeError.serverInternal, "error revoking the certificate");
        }

        ErrorEntry errorEntry = sdkResp.getEntries()[0].getError();
        if (errorEntry == null) {
          return toHttpResponse(HttpRespContent.of(SC_OK, null, null));
        } else {
          int errCode = errorEntry.getCode();
          if (errCode == ErrorCode.CERT_REVOKED.getCode()) {
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.alreadyRevoked, null);
          } else if (errCode == ErrorCode.UNKNOWN_CERT.getCode()) {
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.malformed, "certificate is unknown");
          } else {
            throw new AcmeProtocolException(SC_FORBIDDEN,
                AcmeError.unauthorized, null);
          }
        }
      }
      case CMD_orders: {
        // clean the orders.
        cleanOrders();

        Long id = toLongId(tokens[1]);
        if (id == null || id != account.getId()) {
          throw new AcmeProtocolException(SC_NOT_FOUND,
              AcmeError.accountDoesNotExist, null);
        }

        List<Long> orderIds = repo.getOrderIds(id);
        int size = orderIds == null ? 0 : orderIds.size();
        List<String> urls = new ArrayList<>(size);
        if (orderIds != null) {
          for (Long orderId : orderIds) {
            urls.add(baseUrl + "order/" + AcmeUtils.toBase64(orderId));
          }
        }
        return buildSuccJsonResp(SC_OK, new OrdersResponse(urls));
      }
      case CMD_newOrder: {
        NewOrderPayload newOrderReq = NewOrderPayload.parse(toJsonMap(
            decodeFast(body.getPayload())));
        List<Identifier> identifiers = newOrderReq.getIdentifiers();
        int size = identifiers == null ? 0 : identifiers.size();

        if (size == 0) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
              "no identifier is specified");
        }

        int numChalls = 0;
        for (Identifier identifier : identifiers) {
          String type = identifier.getType();
          String value = identifier.getValue();

          if ("dns".equals(type)) {
            if (!value.startsWith("*.")) {
              if (challengeTypes.contains(HTTP_01)) {
                numChalls++;
              }

              if (challengeTypes.contains(TLS_ALPN_01)) {
                numChalls++;
              }
            }

            if (challengeTypes.contains(DNS_01)) {
              numChalls++;
            }

            if (numChalls == 0) {
              throw new AcmeProtocolException(SC_BAD_REQUEST,
                  AcmeError.unsupportedIdentifier,
                  "unsupported identifier '" + type + "/" + value + "'");
            }
          } else {
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.unsupportedIdentifier,
                "unsupported identifier type '" + type + "'");
          }
        }

        // 7 days validity
        Instant expires = Instant.now().truncatedTo(ChronoUnit.SECONDS)
                          .plus(7, ChronoUnit.DAYS);

        List<AcmeAuthz> authzs = new ArrayList<>(size);

        AcmeRepo.IdsForOrder ids = repo.newIdsForOrder(size, numChalls);
        int[] authzIds = ids.getAuthzSubIds();
        int[] challIds = ids.getChallSubIds();

        int authzIdOffset = 0;
        int challIdOffset = 0;

        for (Identifier identifier : identifiers) {
          AcmeAuthz authz = new AcmeAuthz(authzIds[authzIdOffset++],
                            identifier.toAcmeIdentifier());
          authzs.add(authz);

          authz.setStatus(AuthzStatus.pending);
          authz.setExpires(expires);

          String type = identifier.getType();
          String value = identifier.getValue();
          String token = rndToken();

          if ("dns".equals(type)) {
            String v = value;
            if (v.startsWith("*.")) {
              v = v.substring(2);
            }

            if (v.indexOf('*') != -1) {
              throw new AcmeProtocolException(SC_BAD_REQUEST,
                  AcmeError.unsupportedIdentifier,
                  "unsupported identifier '" + value + "'");
            }

            String jwkSha256 = account.getJwkSha256();

            String authorization = token + "." + jwkSha256;
            String authorizationSha256 = Base64.getUrlNoPaddingEncoder()
                .encodeToString(HashAlgo.SHA256.hash(
                    authorization.getBytes(StandardCharsets.UTF_8)));

            List<AcmeChallenge> challenges = new ArrayList<>(3);
            if (!value.startsWith("*.")) {
              if (challengeTypes.contains(HTTP_01)) {
                challenges.add(newChall(challIds[challIdOffset++],
                    HTTP_01, token, authorization));
              }

              if (challengeTypes.contains(TLS_ALPN_01)) {
                challenges.add(newChall(challIds[challIdOffset++], TLS_ALPN_01,
                    token, authorizationSha256));
              }
            }

            if (challengeTypes.contains(DNS_01)) {
              challenges.add(newChall(challIds[challIdOffset++], DNS_01,
                  token, authorizationSha256));
            }
            authz.setChallenges(challenges);
          } else {
            throw new AcmeProtocolException(SC_BAD_REQUEST,
                AcmeError.unsupportedIdentifier,
                "unsupported identifier type '" + type + "'");
          }
        }

        AcmeOrder order = repo.newAcmeOrder(account.getId(), ids.getOrderId());
        order.setAuthzs(authzs);

        Instant notBefore = null;
        Instant notAfter = null;
        if (newOrderReq.getNotBefore() != null) {
          notBefore = AcmeUtils.parseTimestamp(newOrderReq.getNotBefore());
        }

        if (newOrderReq.getNotAfter() != null) {
          notAfter = AcmeUtils.parseTimestamp(newOrderReq.getNotAfter());
        }

        order.setExpires(expires);

        if (notBefore != null || notAfter != null)  {
          CertReqMeta certReqMeta = new CertReqMeta();
          certReqMeta.setNotBefore(notBefore);
          certReqMeta.setNotAfter(notAfter);
          order.setCertReqMeta(certReqMeta);
        }

        repo.addOrder(order);
        OrderResponse orderResp = order.toResponse(baseUrl);

        if (LOG.isInfoEnabled()) {
          LOG.info("added new order {} for identifiers {}: {}", order.idText(),
              identifiers, JsonBuilder.toJson(orderResp.toCodec()));
        }

        return buildSuccJsonResp(SC_CREATED, orderResp)
            .putHeader(HDR_LOCATION, order.getLocation(baseUrl));
      }
      case CMD_order: {
        String id = tokens[1];
        AcmeOrder order = getOrder(id);
        return buildSuccJsonResp(SC_OK, order.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, order.getLocation(baseUrl));
      }
      case CMD_finalize: {
        String id = tokens[1];
        AcmeOrder order = getOrder(id);
        order.updateStatus();

        // check whether all authorizations have been finished
        switch (order.getStatus()) {
          case ready:
            break;
          case pending:
            throw new AcmeProtocolException(SC_FORBIDDEN,
                AcmeError.orderNotReady, "Order is not ready");
          case invalid:
            throw new AcmeProtocolException(SC_FORBIDDEN,
                AcmeError.unauthorized, "Order is invalid");
          case processing:
            throw new AcmeProtocolException(SC_FORBIDDEN,
                AcmeError.orderNotReady, "Enrolling certificate is processing");
          case valid:
            throw new AcmeProtocolException(SC_FORBIDDEN,
                AcmeError.orderNotReady, "Certificate has been issued");
          default:
            throw new RuntimeException(
                "should not reach here, invalid order status "
                + order.getStatus());
        }

        FinalizeOrderPayload finalizeOrderReq = FinalizeOrderPayload.parse(
            toJsonMap(decodeFast(body.getPayload())));

        byte[] csrBytes;
        CertificationRequest csr;
        try {
          csrBytes = decodeFast(finalizeOrderReq.getCsr());
          csr = GatewayUtil.parseCsrInRequest(csrBytes);
        } catch (Exception e) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
              "could not parse CSR");
        }

        String keyAlgOid = csr.getCertificationRequestInfo()
            .getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();

        AcmeProtocolConf.CaProfile caProfile = Optional.ofNullable(
            getCaProfile(keyAlgOid)).orElseThrow(
                () -> new AcmeProtocolException(SC_BAD_REQUEST,
                    AcmeError.badCSR, "unsupported key type " + keyAlgOid));

        // verify the CSR
        Set<Identifier> identifiers = new HashSet<>();
        for (AcmeAuthz authz : order.getAuthzs()) {
          identifiers.add(authz.getIdentifier().toIdentifier());
        }

        X500Name csrSubject = csr.getCertificationRequestInfo().getSubject();
        String cn = X509Util.getCommonName(csrSubject);
        if (cn != null && !cn.isEmpty()) {
          boolean match = false;
          for (Identifier identifier : identifiers) {
            if (identifier.getValue().equals(cn)) {
              match = true;
              break;
            }
          }

          if (!match) {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
                "invalid commonName in CSR");
          }
        }

        Extensions csrExtensions = X509Util.getExtensions(
            csr.getCertificationRequestInfo());

        byte[] sanExtnValue = csrExtensions == null ? null
            : X509Util.getCoreExtValue(
                csrExtensions, OIDs.Extn.subjectAlternativeName);
        if (sanExtnValue == null) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
              "no extension subjectAlternativeName in CSR");
        }

        GeneralNames generalNames = GeneralNames.getInstance(sanExtnValue);
        String firstSanValue = null;
        for (GeneralName gn : generalNames.getNames()) {
          int tagNo = gn.getTagNo();
          if (tagNo == GeneralName.dNSName) {
            String value =
                ASN1IA5String.getInstance(gn.getName()).getString();
            if (firstSanValue == null) {
              firstSanValue = value;
            }

            Identifier matchedId = null;
            for (Identifier identifier : identifiers) {
              if ("dns".equalsIgnoreCase(identifier.getType())
                  && value.equals(identifier.getValue())) {
                matchedId = identifier;
                break;
              }
            }

            if (matchedId != null) {
              identifiers.remove(matchedId);
            } else {
              throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
                  "invalid DNS identifier in the extension" +
                  " subjectAlternativeName in CSR: " + value);
            }
          } else {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
                "unsupported name in the extension subjectAlternativeName " +
                "in CSR.");
          }
        }

        if (!identifiers.isEmpty()) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
              "missing identifier in the extension subjectAlternativeName " +
              "in CSR: " + identifiers);
        }

        try {
          if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
                "could not verify signature of CSR");
          }
        } catch (Exception ex) {
          LogUtil.error(LOG, ex, "error verifying CSR");
          throw new AcmeProtocolException(SC_BAD_REQUEST,
              AcmeError.badCSR, null);
        }

        CertReqMeta certReqMeta = order.getCertReqMeta();
        if (certReqMeta == null) {
          certReqMeta = new CertReqMeta();
          order.setCertReqMeta(certReqMeta);
        }

        if (cn == null || cn.isEmpty()) {
          // DNS
          certReqMeta.setSubject("CN=" + firstSanValue);
        }

        certReqMeta.setCa(caProfile.getCa());
        certReqMeta.setCertProfile(caProfile.getTlsProfile());

        order.setCsr(csrBytes);
        order.setStatus(OrderStatus.processing);

        LOG.info("finalized order {}", order.idText());

        return buildSuccJsonResp(SC_OK, order.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, order.getLocation(baseUrl));
      }
      case CMD_cert: {
        String id = tokens[1];
        AcmeOrder order = getOrder(id);
        byte[] certBytes = Optional.ofNullable(order.getCert()).orElseThrow(
            () -> new AcmeProtocolException(SC_NOT_FOUND,
                AcmeError.orderNotReady, "found no certificate"));

        byte[] encodedIssuer = X509Util.extractCertIssuer(certBytes);
        String hexIssuer = Hex.encode(encodedIssuer);
        byte[][] cacerts = cacertsMap.get(hexIssuer);

        if (cacerts == null) {
          try {
            cacerts = sdk.cacertsBySubject(encodedIssuer);
          } catch (SdkErrorResponseException e) {
            throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR,
                AcmeError.serverInternal,
                "could not retrieve CA certificate chain");
          }

          String hexCaSubject = Hex.encode(
              X509Util.extractCertSubject(cacerts[0]));

          if (!hexIssuer.equals(hexCaSubject)) {
            throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR,
                AcmeError.serverInternal,
                "could not retrieve CA certificate chain");
          }
          cacertsMap.put(hexCaSubject, cacerts);
        }

        byte[][] certchain = new byte[1 + cacerts.length][];
        certchain[0] = certBytes;
        System.arraycopy(cacerts, 0, certchain, 1, cacerts.length);

        byte[] respBytes = StringUtil.toUtf8Bytes(
            X509Util.encodeCertificates(certchain));

        LOG.info("downloaded certificate of order {}", order.idText());
        return toHttpResponse(
            HttpRespContent.ofOk(CT_PEM_CERTIFICATE_CHAIN, respBytes));
      }
      case CMD_authz: {
        if (tokens.length != 2) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown authz",
              AuditLevel.ERROR, AuditStatus.FAILED);
        }

        AuthzId id = new AuthzId(decodeFast(tokens[1]));
        AcmeAuthz authz = Optional.ofNullable(repo.getAuthz(id)).orElseThrow(
            () -> new HttpRespAuditException(SC_NOT_FOUND, "unknown authz",
                AuditLevel.ERROR, AuditStatus.FAILED));

        if (LOG.isInfoEnabled()) {
          LOG.info("downloaded authz {}: {}", id, JsonBuilder.toJson(
              authz.toResponse(baseUrl, id.getOrderId()).toCodec()));
        }
        return buildSuccJsonResp(SC_OK,
            authz.toResponse(baseUrl, id.getOrderId()));
      }
      case CMD_chall: {
        if (tokens.length != 2) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown challenge",
              AuditLevel.ERROR, AuditStatus.FAILED);
        }

        ChallId challId = new ChallId(decodeFast(tokens[1]));
        AcmeChallenge2 chall2 = Optional.ofNullable(
            repo.getChallenge(challId)).orElseThrow(
                () -> new HttpRespAuditException(SC_NOT_FOUND,
                    "unknown challenge", AuditLevel.ERROR, AuditStatus.FAILED));

        AcmeChallenge chall = chall2.getChallenge();

        ChallengeStatus status = chall.getStatus();
        if (status == ChallengeStatus.pending) {
          chall.setStatus(ChallengeStatus.processing);
        }
        ChallengeResponse resp = chall.toChallengeResponse(baseUrl,
            challId.getOrderId(), challId.getAuthzId());

        LOG.info("Received ready for challenge {} of order {}",
            challId, challId.getOrderId());
        //.putHeader(HDR_RETRY_AFTER, "2"); // wait for 2 seconds
        HttpResponse ret = buildSuccJsonResp(SC_OK, resp);
        String authzUrl = chall2.getChallenge().getAuthz().getUrl(baseUrl);
        ret.putHeader(HDR_LINK, "<" + authzUrl + ">;rel=\"up\"");
        return ret;
      }
      default: {
        throw new HttpRespAuditException(SC_NOT_FOUND,
            "unknown command " + command,
            AuditLevel.ERROR, AuditStatus.FAILED);
      }
    }
  } // method service

  private HttpResponse toHttpResponse(HttpRespContent respContent) {
    return (respContent == null)
        ? new HttpResponse(SC_OK)
        : new HttpResponse(respContent.getStatusCode(),
            respContent.getContentType(), null,
            respContent.isBase64(), respContent.getContent());
  }

  private AcmeOrder getOrder(String id)
      throws HttpRespAuditException, AcmeSystemException {
    Long lLabel = toLongId(id);
    return Optional.ofNullable(lLabel == null ? null
        : repo.getOrder(lLabel)).orElseThrow(
            () -> new HttpRespAuditException(SC_NOT_FOUND, "unknown order",
                AuditLevel.ERROR, AuditStatus.FAILED));
  }

  private HttpResponse buildSuccJsonResp(int statusCode, JsonEncodable body) {
    return toHttpResponse(HttpRespContent.of(statusCode, CT_JSON,
        StringUtil.toUtf8Bytes(JsonBuilder.toJson(body.toCodec()))));
  }

  private HttpResponse buildProblemResp(int statusCode, Problem problem) {
    String text = JsonBuilder.toJson(problem.toCodec());
    byte[] bytes = StringUtil.toUtf8Bytes(text);
    return toHttpResponse(
        HttpRespContent.of(statusCode, CT_PROBLEM_JSON, bytes));
  }

  private void verifySignature(
      String sigAlg, PublicKey pubKey, JoseMessage joseMessage)
      throws AcmeProtocolException {
    sigAlg = sigAlg.toUpperCase(Locale.ROOT);
    SignAlgo signAlgo = joseAlgMap.get(sigAlg);
    if (signAlgo == null) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.badSignatureAlgorithm,
          "unsupported signature algorrihm " + sigAlg);
    }

    try {
      Signature sig = signAlgo.newSignature();
      sig.initVerify(pubKey);
      sig.update(joseMessage.getProtected().getBytes(StandardCharsets.UTF_8));
      sig.update((byte) 0x2e); // 0x2e = '.'
      sig.update(joseMessage.getPayload().getBytes(StandardCharsets.UTF_8));
      boolean sigValid = sig.verify(decodeFast(joseMessage.getSignature()));
      if (!sigValid) {
        throw new AcmeProtocolException(SC_BAD_REQUEST,
            AcmeError.malformed, "signature is not valid");
      }
    } catch (NoSuchAlgorithmException e) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.badSignatureAlgorithm, e.getMessage());
    } catch (InvalidKeyException e) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.badPublicKey, "public key is bad");
    } catch (SignatureException e) {
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.malformed, "signature is not valid");
    }
  }

  private void verifyContacts(List<String> contacts)
      throws AcmeProtocolException {
    if (contacts == null || contacts.isEmpty()) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.invalidContact,
          "no contact is specified");
    }

    for (String contact : contacts) {
      int rc = contactVerifier.verfifyContact(contact);
      if (rc == ContactVerifier.unsupportedContact) {
        throw new AcmeProtocolException(SC_BAD_REQUEST,
            AcmeError.unsupportedContact,
            "unsupported contact '" + contact + "'");
      } else if (rc == ContactVerifier.invalidContact) {
        throw new AcmeProtocolException(SC_BAD_REQUEST,
            AcmeError.invalidContact,
            "invalid contact '" + contact + "'");
      }
    }
  }

  private String rndToken() {
    byte[] token = new byte[tokenNumBytes];
    rnd.nextBytes(token);
    return Base64.getUrlNoPaddingEncoder().encodeToString(token);
  }

  private AcmeChallenge newChall(
      int subId, String type, String token, String expectedAuthorization) {
    return new AcmeChallenge(type, subId, token, expectedAuthorization,
        ChallengeStatus.pending);
  }

  private void cleanOrders() {
    synchronized (lastOrdersCleaned) {
      Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
      Instant last = Instant.ofEpochSecond(lastOrdersCleaned.get());
      if (Duration.between(last, now).compareTo(Duration.ofDays(1)) < 0) {
        // last cleanup was still within 1 day
        return;
      }

      lastOrdersCleaned.set(now.getEpochSecond());
      Instant certExpired =
          now.minus(cleanOrderConf.getExpiredCertDays(), ChronoUnit.DAYS);
      Instant notFinishedOrderExpires =
          now.minus(cleanOrderConf.getExpiredOrderDays(), ChronoUnit.DAYS);

      Thread thread = new Thread(() -> {
        try {
          int num = repo.cleanOrders(certExpired, notFinishedOrderExpires);
          LOG.info("removed {} orders with cert.notAfter < {} or " +
                  "not-finished-order.expires < {}",
              num, certExpired, notFinishedOrderExpires);
        } catch (Exception e) {
          LogUtil.error(LOG, e, "error cleaning orders");
        }
      });
      thread.setDaemon(true);
      thread.start();
    }
  }

  private static Long toLongId(String id) {
    return (id.length() != 11) ? null
        : Pack.littleEndianToLong(decodeFast(id), 0);
  }

  private AcmeProtocolConf.CaProfile getCaProfile(String keyAlgId) {
    for (AcmeProtocolConf.CaProfile caProfile : caProfiles) {
      if (caProfile.getKeyTypes().contains(keyAlgId)) {
        return caProfile;
      }
    }

    return null;
  }

  private static JsonMap toJsonMap(byte[] bytes) throws AcmeProtocolException {
    try {
      return JsonParser.parseMap(bytes, false);
    } catch (CodecException e) {
      LOG.warn("could not parse request", e);
      throw new AcmeProtocolException(SC_BAD_REQUEST,
          AcmeError.malformed, "invalid request");
    }
  }

}
