// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.Pack;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.gateway.RestResponse;
import org.xipki.ca.gateway.acme.msg.*;
import org.xipki.ca.gateway.acme.type.*;
import org.xipki.ca.gateway.acme.util.AcmeJson;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.ca.sdk.*;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.JSON;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.HttpRespContent;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.ca.gateway.acme.AcmeConstants.*;
import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Base64Url.decodeFast;
import static org.xipki.util.StringUtil.isBlank;
import static org.xipki.util.exception.ErrorCode.UNKNOWN_CERT;

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

    public HttpRespAuditException(int httpStatus, String auditMessage,
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

  private static final Logger LOG = LoggerFactory.getLogger(AcmeResponder.class);

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

  private final List<AcmeProxyConf.CaProfile> caProfiles;

  private final Set<String> challengeTypes;

  private final SecureRandom rnd;

  private final AcmeRepo repo;

  private final Map<String, byte[][]> cacertsMap = new ConcurrentHashMap<>();

  private final int tokenNumBytes;

  private final AcmeProxyConf.CleanupOrderConf cleanOrderConf;

  private final ChallengeValidator challengeValidator;

  private final CertEnroller certEnroller;

  private final AtomicLong lastOrdersCleaned = new AtomicLong(0);

  static {
    knownCommands = CollectionUtil.asUnmodifiableSet(
        CMD_directory, CMD_newNonce, CMD_newAccount, CMD_newOrder, CMD_revokeCert, CMD_keyChange,
        CMD_account, CMD_order, CMD_orders, CMD_authz, CMD_chall, CMD_finalize, CMD_cert);
  }

  public AcmeResponder(SdkClient sdk, SecurityFactory securityFactory, PopControl popControl, AcmeProxyConf.Acme conf)
      throws InvalidConfException {
    this.sdk = notNull(sdk, "sdk");
    this.popControl = notNull(popControl, "popControl");
    this.securityFactory = notNull(securityFactory, "securityFactory");

    this.baseUrl = notBlank(conf.getBaseUrl(), "baseUrl");
    this.accountPrefix = this.baseUrl + "acct/";
    this.cleanOrderConf = new AcmeProxyConf.CleanupOrderConf();
    AcmeProxyConf.CleanupOrderConf cleanOrder = conf.getCleanupOrder();
    if (cleanOrder == null) {
      this.cleanOrderConf.setExpiredOrderDays(365);
      this.cleanOrderConf.setExpiredCertDays(365);
    } else {
      // minimal 10 days
      this.cleanOrderConf.setExpiredCertDays(Math.max(10, cleanOrder.getExpiredCertDays()));
      this.cleanOrderConf.setExpiredOrderDays(Math.max(10, cleanOrder.getExpiredOrderDays()));
    }

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
      if (!(types.contains(DNS_01) || types.contains(HTTP_01) || types.contains(TLS_ALPN_01))) {
        throw new InvalidConfException("invalid challengeTypes '" + types + "'");
      }
      challengeTypes = new HashSet<>(types);
    } else {
      challengeTypes = new HashSet<>(4);
      challengeTypes.add(DNS_01);
      challengeTypes.add(HTTP_01);
      challengeTypes.add(TLS_ALPN_01);
    }
    LOG.info("challenge types: {}", challengeTypes);

    StringBuilder sb = new StringBuilder();
    sb.append("{");
    addJsonField(sb, "newNonce",   baseUrl + CMD_newNonce);
    addJsonField(sb, "newAccount", baseUrl + CMD_newAccount);
    addJsonField(sb, "newOrder",   baseUrl + CMD_newOrder);
    // newAuthz is not supported
    //addJsonField(sb, "newAuthz", baseUrl + CMD_newAuthz);
    addJsonField(sb, "revokeCert", baseUrl + CMD_revokeCert);
    addJsonField(sb, "keyChange",  baseUrl + CMD_keyChange);

    sb.append(addQuoteSign("meta")).append(":{");
    if (StringUtil.isNotBlank(conf.getWebsite())) {
      addJsonField(sb, "website", conf.getWebsite());
    }

    this.termsOfServicePresent = StringUtil.isNotBlank(conf.getTermsOfService());
    if (termsOfServicePresent) {
      addJsonField(sb, "termsOfService", conf.getTermsOfService());
    }

    if (CollectionUtil.isNotEmpty(conf.getCaaIdentities())) {
      sb.append(addQuoteSign("caaIdentities")).append(":[");
      for (String caIdentity : conf.getCaaIdentities()) {
        sb.append(addQuoteSign(caIdentity)).append(",");
      }

      // remove the last ','
      sb.deleteCharAt(sb.length() - 1);
      sb.append("],");
    }

    sb.append(addQuoteSign("externalAccountRequired")).append(":false");
    sb.append("}}");
    this.directoryBytes = sb.toString().getBytes(StandardCharsets.UTF_8);

    String str = conf.getContactVerifier();
    if (str != null) {
      str = str.trim();
    }

    if (str == null || str.isEmpty()) {
      this.contactVerifier = new ContactVerifier.DfltContactVerifier();
    } else {
      try {
        this.contactVerifier = (ContactVerifier) Class.forName(str).getConstructor().newInstance();
      } catch (Exception e) {
        throw new RuntimeException("invalid contactVerifier '" + str + "'");
      }
    }

    rnd = new SecureRandom();

    if (conf.getDbConf() == null) {
      throw new InvalidConfException("dbConf is not specified");
    }

    try {
      FileOrValue fileOrValue = new FileOrValue();
      fileOrValue.setFile(conf.getDbConf());
      DataSourceWrapper dataSource0 = new DataSourceFactory().createDataSource(
          "acme-db", fileOrValue, securityFactory.getPasswordResolver());
      repo = new AcmeRepo(new AcmeDataSource(dataSource0), conf.getCacheSize(), conf.getSyncDbSeconds());
    } catch (Exception ex) {
      throw new InvalidConfException("could not initialize database", ex);
    }

    this.challengeValidator = new ChallengeValidator(repo);
    this.certEnroller = new CertEnroller(repo, sdk);
  }

  private static String addQuoteSign(String text) {
    return "\"" + text + "\"";
  }

  private static void addJsonField(StringBuilder sb, String name, String value) {
    sb.append(addQuoteSign(name)).append(":").append(addQuoteSign(value)).append(",");
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

  public RestResponse service(HttpServletRequest servletReq, byte[] request, AuditEvent event) {
    StringContainer command = new StringContainer();

    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    AuditLevel auditLevel = AuditLevel.INFO;
    String auditMessage = null;

    RestResponse resp;
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

      return new RestResponse(ex.getHttpStatus(), null, null, null);
    } catch (AcmeProtocolException ex) {
      auditLevel = AuditLevel.WARN;
      auditStatus = AuditStatus.FAILED;
      auditMessage = ex.getMessage();
      Problem problem = new Problem();
      problem.setType(ex.getAcmeError().getQualifiedCode());
      problem.setDetail(ex.getAcmeDetail());
      return buildProblemResp(ex.getHttpError(), problem);
    } catch (DataAccessException | AcmeSystemException ex) {
      LogUtil.error(LOG, ex, null);
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      if (ex instanceof DataAccessException) {
        auditMessage = "database error";
      } else {
        auditMessage = "ACME system exception";
      }
      return new RestResponse(SC_INTERNAL_SERVER_ERROR, null, null, null);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      return new RestResponse(SC_INTERNAL_SERVER_ERROR, null, null, null);
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

  private RestResponse doService(HttpServletRequest servletReq, byte[] request,
      AuditEvent event, StringContainer commandContainer)
      throws HttpRespAuditException, AcmeProtocolException, AcmeSystemException, DataAccessException {
    String method = servletReq.getMethod();
    String path = servletReq.getServletPath();

    String[] tokens;
    String hdrHost = servletReq.getHeader(HDR_HOST);
    if (!host.equals(hdrHost) && !host2.equals(hdrHost)) {
      String message = "invalid header host '" + hdrHost + "'";
      LOG.error(message);
      throw new HttpRespAuditException(SC_BAD_REQUEST, message, AuditLevel.ERROR, AuditStatus.FAILED);
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
      throw new HttpRespAuditException(SC_NOT_FOUND, message, AuditLevel.ERROR, AuditStatus.FAILED);
    }

    String command = tokens[0].toLowerCase(Locale.ROOT);
    commandContainer.text = command;

    if (isBlank(command)) {
      command = CMD_directory;
    }

    event.addEventType(command);

    if (!knownCommands.contains(command)) {
      String message = "invalid command '" + command + "'";
      LOG.error(message);
      throw new HttpRespAuditException(SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    if (CMD_newNonce.equalsIgnoreCase(command)) {
      int sc = "HEAD".equals(method) ? SC_OK
          : "GET" .equals(method) ? SC_NO_CONTENT : 0;
      if (sc == 0) {
        throw new HttpRespAuditException(SC_METHOD_NOT_ALLOWED, "HTTP method not allowed: " + method,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      return new RestResponse(sc, null, null, null)
          .putHeader("Cache-Control", "no-store");
    } else if (CMD_directory.equalsIgnoreCase(command)) {
      if (!"GET".equals(method)) {
        throw new HttpRespAuditException(SC_METHOD_NOT_ALLOWED, "HTTP method not allowed: " + method,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      HttpRespContent respContent = HttpRespContent.ofOk(CT_JSON, false, directoryBytes);
      return new RestResponse(SC_OK, respContent.getContentType(), null,
          respContent.isBase64(), respContent.getContent());
    }

    if (!"POST".equals(method)) {
      throw new HttpRespAuditException(SC_METHOD_NOT_ALLOWED, "HTTP method not allowed: " + method,
          AuditLevel.INFO, AuditStatus.FAILED);
    }

    String contentType = servletReq.getContentType();
    if (!CT_JOSE_JSON.equals(contentType)) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "invalid Content-Type '" + contentType + "'");
    }

    JoseMessage body = JSON.parseObject(request, JoseMessage.class);
    AcmeJson protected_= AcmeJson.parse(decodeFast(body.getProtected()));

    if (!protected_.contains("url")) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "url is not present");
    }

    String protectedUrl = protected_.get("url").asString();
    if (!protectedUrl.equals(baseUrl + path.substring(1))) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "url is not valid: '" + protectedUrl + "'");
    }

    if (!protected_.contains("nonce")) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badNonce, "nonce is not present");
    }

    String nonce = protected_.get("nonce").asString();
    if (!nonceManager.removeNonce(nonce)) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badNonce, null);
    }

    final int MASK_JWK = 1; // jwk is allowed
    final int MASK_KID = 2; // kid is allowed

    int verificationKeyRequirement = CMD_newAccount.equals(command) ? MASK_JWK
        : CMD_revokeCert.equals(command) ? MASK_JWK | MASK_KID : MASK_KID;

    boolean withJwk = protected_.contains("jwk");
    boolean withKid = protected_.contains("kid");

    AcmeAccount account = null;
    String kid = null;
    Map<String, String> jwk = null;
    PublicKey pubKey;

    if (withKid && withJwk) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "Both jwk and kid are specified, but exactly one of them is allowed");
    } else if (withJwk) {
      if ((verificationKeyRequirement & MASK_JWK) == 0) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "kid is specified, but jwk is allowed");
      }

      jwk = AcmeUtils.jsonToMap(protected_.get("jwk").asObject());
      try {
        pubKey = AcmeUtils.jwkPublicKey(jwk);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "jwkPublicKey");
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badPublicKey, null);
      }
    } else if (protected_.contains("kid")) {
      if ((verificationKeyRequirement & MASK_KID) == 0) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
            "jwk is specified, but only kid is allowed");
      }

      // extract the location
      kid = protected_.get("kid").asString();
      if (kid.startsWith(accountPrefix)) {
        Long id = toLongId(kid.substring(accountPrefix.length()));
        if (id != null) {
          account = repo.getAccount(id);
        }
      }

      if (account == null) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.accountDoesNotExist, null);
      }

      try {
        pubKey = account.getPublicKey();
      } catch (InvalidKeySpecException e) {
        throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR, AcmeError.badPublicKey, null);
      }
    } else {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed,
          "None of jwk and kid is specified, but one of them is required");
    }

    // pre-check
    if (CMD_account.equals(command)) {
      if (!protected_.get("url").asString().equals(kid)) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "kid and url do not match");
      }
    }

    // assert the account is valid
    if (account != null) {
      if (account.getStatus() != AccountStatus.valid) {
        throw new AcmeProtocolException(SC_UNAUTHORIZED, AcmeError.unauthorized, "account is not valid");
      }
    }

    RestResponse verifyRes = verifySignature(pubKey, body);
    if (verifyRes != null) {
      return verifyRes;
    }

    switch (command) {
      case CMD_newAccount: {
        NewAccountPayload reqPayload = JSON.parseObject(decodeFast(body.getPayload()), NewAccountPayload.class);

        AcmeAccount existingAccount = repo.getAccountForJwk(jwk);
        if (existingAccount != null) {
          return buildSuccJsonResp(SC_OK, existingAccount.toResponse(baseUrl))
              .putHeader(HDR_LOCATION, existingAccount.getLocation(baseUrl));
        }

        Boolean onlyReturnExisting = reqPayload.getOnlyReturnExisting();
        if (onlyReturnExisting != null && onlyReturnExisting) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.accountDoesNotExist, null);
        }

        // create a new account
        Boolean b = reqPayload.getTermsOfServiceAgreed();
        boolean tosAgreed = (b != null) ? b : !termsOfServicePresent;

        if (!tosAgreed) {
          throw new AcmeProtocolException(SC_UNAUTHORIZED, AcmeError.userActionRequired,
              "terms of service has not been agreed");
        }

        AcmeAccount newAccount = repo.newAcmeAccount();
        List<String> contacts = reqPayload.getContact();
        if (contacts != null && !contacts.isEmpty()) {
          RestResponse verifyErrorResp = verifyContacts(contacts);
          if (verifyErrorResp != null) {
            return verifyErrorResp;
          }
          newAccount.setContact(contacts);
        }
        newAccount.setExternalAccountBinding(reqPayload.getExternalAccountBinding());
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
        JoseMessage reqPayload = JSON.parseObject(decodeFast(body.getPayload()), JoseMessage.class);
        AcmeJson innerProtected = AcmeJson.parse(decodeFast(reqPayload.getProtected()));

        Map<String, String> newJwk = AcmeUtils.jsonToMap(innerProtected.get("jwk").asObject());
        AcmeAccount accountForNewJwk = repo.getAccountForJwk(newJwk);
        if (accountForNewJwk != null) {
          // jwk not exists.
          return toRestResponse(HttpRespContent.of(SC_CONFLICT, null, null))
              .putHeader(HDR_LOCATION, accountForNewJwk.getLocation(baseUrl));
        }

        // check payload.account, and payload.oldKey
        AcmeJson innerPayload = AcmeJson.parse(decodeFast(reqPayload.getPayload()));
        String innerAccount = innerPayload.get("account").asString();
        if (!innerAccount.equals(kid)) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "invalid payload.account");
        }

        Map<String, String> oldKey = AcmeUtils.jsonToMap(innerPayload.get("oldKey").asObject());
        if (!account.hasJwk(oldKey)) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "oldKey does not match the account");
        }

        // check inner signature (by the new key)
        PublicKey newPubKey;
        try {
          newPubKey = AcmeUtils.jwkPublicKey(newJwk);
        } catch (InvalidKeySpecException e) {
          LogUtil.error(LOG, e, "jwkPublicKey");
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badPublicKey, null);
        }

        verifyRes = verifySignature(newPubKey, reqPayload);
        if (verifyRes != null) {
          return verifyRes;
        }

        account.setJwk(newJwk);

        LOG.info("changed key of account {}", account.idText());
        return buildSuccJsonResp(SC_OK, account.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, account.getLocation(baseUrl));
      }
      case CMD_account: {
        AccountResponse reqPayload = JSON.parseObject(decodeFast(body.getPayload()), AccountResponse.class);
        AccountStatus status = reqPayload.getStatus();

        if (status == AccountStatus.revoked) {
          throw new AcmeProtocolException(SC_UNAUTHORIZED, AcmeError.unauthorized, "status revoked is not allowed");
        }

        if (status == AccountStatus.deactivated) {
          // 7.3.6.  Account Deactivation
          account.setStatus(AccountStatus.deactivated);
        }

        // 7.3.2.  Account Update
        List<String> contacts = reqPayload.getContact();
        if (contacts != null && !contacts.isEmpty()) {
          RestResponse errResp = verifyContacts(contacts);
          if (errResp != null) {
            return errResp;
          }

          account.setContact(contacts);
        }

        LOG.info("updated account {}", account.idText());
        return buildSuccJsonResp(SC_OK, account.toResponse(baseUrl));
      }
      case CMD_revokeCert: {
        RevokeCertPayload reqPayload = JSON.parseObject(decodeFast(body.getPayload()), RevokeCertPayload.class);
        Integer reasonCode = reqPayload.getReason();
        CrlReason reason;
        try {
          reason = reasonCode == null ? CrlReason.UNSPECIFIED : CrlReason.forReasonCode(reasonCode);
        } catch (Exception e) {
          reason = null;
        }

        if (reason == null || !CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(reason)) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badRevocationReason,
              "bad revocation reason " + reasonCode);
        }

        byte[] certBytes = decodeFast(reqPayload.getCertificate());

        Certificate cert;
        byte[] encodedIssuer;
        try {
          cert = Certificate.getInstance(certBytes);
          encodedIssuer = cert.getIssuer().getEncoded();
        } catch (Exception e) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "malformed certificate");
        }

        LOG.info("try to revoke certificate with (subject={}, issuer={}, serialNumber={})",
            cert.getSubject(), cert.getIssuer(), cert.getSerialNumber());

        if (jwk != null) {
          // request is signed with the private paired with the certificate.
          boolean jwkAndCertMatch;
          try {
            jwkAndCertMatch = AcmeUtils.matchKey(jwk, cert.getSubjectPublicKeyInfo());
          } catch (InvalidKeySpecException e) {
            LogUtil.error(LOG, e, "matchKey");
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badPublicKey, "bad jwk");
          }
          if (!jwkAndCertMatch) {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unauthorized, "jwk and certificate do not match");
          }
        }

        AcmeOrder order = repo.getOrderForCert(certBytes);
        if (order == null) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unauthorized,
              "certificate not enrolled through this ACME server");
        }

        if (jwk == null) {
          // account is non-null here.
          // request is signed with the account keypair.
          // assert the certificate is owned by the account
          if (order.getAccountId() != account.getId()) {
            // certificate has not been issued to the given account.
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unauthorized,
                "account and certificate do not match");
          }
        }

        RevokeCertsRequest sdkReq = new RevokeCertsRequest();
        sdkReq.setIssuer(new X500NameType());
        sdkReq.getIssuer().setEncoded(encodedIssuer);

        RevokeCertRequestEntry sdkEntry = new RevokeCertRequestEntry();
        sdkEntry.setReason(reason);
        sdkEntry.setSerialNumber(cert.getSerialNumber().getPositiveValue());
        sdkReq.setEntries(Collections.singletonList(sdkEntry));

        RevokeCertsResponse sdkResp;
        try {
          sdkResp = sdk.revokeCerts(sdkReq);
          LOG.info("revoked certificate");
        } catch (IOException | SdkErrorResponseException e) {
          LogUtil.error(LOG, e, "sdk.revokeCerts");
          throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR, AcmeError.serverInternal,
              "error revoking the certificate");
        }

        ErrorEntry errorEntry = sdkResp.getEntries().get(0).getError();
        if (errorEntry == null) {
          return toRestResponse(HttpRespContent.of(SC_OK, null, null));
        } else {
          int errCode = errorEntry.getCode();
          if (errCode == ErrorCode.CERT_REVOKED.getCode()) {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.alreadyRevoked, null);
          } else if (errCode == UNKNOWN_CERT.getCode()) {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "certificate is unknown");
          } else {
            throw new AcmeProtocolException(SC_FORBIDDEN, AcmeError.unauthorized, null);
          }
        }
      }
      case CMD_orders: {
        // clean the orders.
        cleanOrders();

        Long id = toLongId(tokens[1]);
        if (id == null || id != account.getId()) {
          throw new AcmeProtocolException(SC_NOT_FOUND, AcmeError.accountDoesNotExist, null);
        }

        List<Long> orderIds = repo.getOrderIds(id);
        int size = orderIds == null ? 0 : orderIds.size();
        List<String> urls = new ArrayList<>(size);
        if (orderIds != null) {
          for (Long orderId : orderIds) {
            urls.add(baseUrl + "order/" + AcmeUtils.toBase64(orderId));
          }
        }
        OrdersResponse resp = new OrdersResponse();
        resp.setOrders(urls);
        return buildSuccJsonResp(SC_OK, resp);
      }
      case CMD_newOrder: {
        NewOrderPayload newOrderReq = JSON.parseObject(decodeFast(body.getPayload()), NewOrderPayload.class);
        List<Identifier> identifiers = newOrderReq.getIdentifiers();
        int size = identifiers == null ? 0 : identifiers.size();

        if (size == 0) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "no identifier is specified");
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
              throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unsupportedIdentifier,
                  "unsupported identifier '" + type + "/" + value + "'");
            }
          } else {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unsupportedIdentifier,
                "unsupported identifier type '" + type + "'");
          }
        }

        // 7 days validity
        Instant expires = Instant.now().truncatedTo(ChronoUnit.SECONDS).plus(7, ChronoUnit.DAYS);

        List<AcmeAuthz> authzs = new ArrayList<>(size);

        AcmeRepo.IdsForOrder ids = repo.newIdsForOrder(size, numChalls);
        int[] authzIds = ids.getAuthzSubIds();
        int[] challIds = ids.getChallSubIds();

        int authzIdOffset = 0;
        int challIdOffset = 0;

        for (Identifier identifier : identifiers) {
          AcmeAuthz authz = new AcmeAuthz(authzIds[authzIdOffset++], identifier.toAcmeIdentifier());
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
              throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unsupportedIdentifier,
                  "unsupported identifier '" + value + "'");
            }

            String jwkSha256 = account.getJwkSha256();

            String authorization = token + "." + jwkSha256;
            String authorizationSha256 = Base64Url.encodeToStringNoPadding(
                HashAlgo.SHA256.hash(authorization.getBytes(StandardCharsets.UTF_8)));

            List<AcmeChallenge> challenges = new ArrayList<>(3);
            if (!value.startsWith("*.")) {
              if (challengeTypes.contains(HTTP_01)) {
                challenges.add(newChall(challIds[challIdOffset++], HTTP_01, token, authorization));
              }

              if (challengeTypes.contains(TLS_ALPN_01)) {
                challenges.add(newChall(challIds[challIdOffset++], TLS_ALPN_01, token, authorizationSha256));
              }
            }

            if (challengeTypes.contains(DNS_01)) {
              challenges.add(newChall(challIds[challIdOffset++], DNS_01, token, authorizationSha256));
            }
            authz.setChallenges(challenges);
          } else {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unsupportedIdentifier,
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
          LOG.info("added new order {} for identifiers {}: {}", order.idText(), identifiers,
              JSON.toJson(orderResp));
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
            throw new AcmeProtocolException(SC_FORBIDDEN, AcmeError.orderNotReady, "Order is not ready");
          case invalid:
            throw new AcmeProtocolException(SC_FORBIDDEN, AcmeError.unauthorized, "Order is invalid");
          case processing:
            throw new AcmeProtocolException(SC_FORBIDDEN, AcmeError.orderNotReady,
                "Enrolling certificate is processing");
          case valid:
            throw new AcmeProtocolException(SC_FORBIDDEN, AcmeError.orderNotReady, "Certificate has been issued");
          default:
            throw new RuntimeException("should not reach here, invalid order status " + order.getStatus());
        }

        FinalizeOrderPayload finalizeOrderReq = JSON.parseObject(decodeFast(body.getPayload()),
            FinalizeOrderPayload.class);

        byte[] csrBytes;
        CertificationRequest csr;
        try {
          csrBytes = Base64Url.decodeFast(finalizeOrderReq.getCsr());
          csr = CertificationRequest.getInstance(csrBytes);
        } catch (Exception e) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR, "could not parse CSR");
        }

        String keyAlgOid =
            csr.getCertificationRequestInfo().getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();
        AcmeProxyConf.CaProfile caProfile = getCaProfile(keyAlgOid);
        if (caProfile == null) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR, "unsupported key type " + keyAlgOid);
        }

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
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR, "invalid commonName in CSR");
          }
        }

        Extensions csrExtensions = X509Util.getExtensions(csr.getCertificationRequestInfo());
        byte[] sanExtnValue = csrExtensions == null ? null
            : X509Util.getCoreExtValue(csrExtensions, Extension.subjectAlternativeName);
        if (sanExtnValue == null) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
              "no extension subjectAlternativeName in CSR");
        }

        GeneralNames generalNames = GeneralNames.getInstance(sanExtnValue);
        String firstSanValue = null;
        for (GeneralName gn : generalNames.getNames()) {
          int tagNo = gn.getTagNo();
          if (tagNo == GeneralName.dNSName) {
            String value = ASN1IA5String.getInstance(gn.getName()).getString();
            if (firstSanValue == null) {
              firstSanValue = value;
            }

            Identifier matchedId = null;
            for (Identifier identifier : identifiers) {
              if ("dns".equalsIgnoreCase(identifier.getType()) && value.equals(identifier.getValue())) {
                matchedId = identifier;
                break;
              }
            }

            if (matchedId != null) {
              identifiers.remove(matchedId);
            } else {
              throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
                  "invalid DNS identifier in the extension subjectAlternativeName in CSR: " + value);
            }
          } else {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
                "unsupported name in the extension subjectAlternativeName in CSR.");
          }
        }

        if (!identifiers.isEmpty()) {
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR,
              "missing identifier in the extension subjectAlternativeName in CSR: " + identifiers);
        }

        try {
          if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
            throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR, "could not verify signature of CSR");
          }
        } catch (Exception ex) {
          LogUtil.error(LOG, ex, "error verifying CSR");
          throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badCSR, null);
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
        byte[] certBytes = order.getCert();
        if (certBytes == null) {
          throw new AcmeProtocolException(SC_NOT_FOUND, AcmeError.orderNotReady, "found no certificate");
        }

        byte[] encodedIssuer = X509Util.extractCertIssuer(certBytes);
        String hexIssuer = Hex.encode(encodedIssuer);
        byte[][] cacerts = cacertsMap.get(hexIssuer);

        if (cacerts == null) {
          try {
            cacerts = sdk.cacertsBySubject(encodedIssuer);
          } catch (IOException | SdkErrorResponseException e) {
            throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR, AcmeError.serverInternal,
                "could not retrieve CA certificate chain");
          }

          String hexCaSubject = Hex.encode(X509Util.extractCertSubject(cacerts[0]));
          if (!hexIssuer.equals(hexCaSubject)) {
            throw new AcmeProtocolException(SC_INTERNAL_SERVER_ERROR, AcmeError.serverInternal,
                "could not retrieve CA certificate chain");
          }
          cacertsMap.put(hexCaSubject, cacerts);
        }

        byte[][] certchain = new byte[1 + cacerts.length][];
        certchain[0] = certBytes;
        System.arraycopy(cacerts, 0, certchain, 1, cacerts.length);

        byte[] respBytes = StringUtil.toUtf8Bytes(X509Util.encodeCertificates(certchain));

        LOG.info("downloaded certificate of order {}", order.idText());
        return toRestResponse(HttpRespContent.ofOk(CT_PEM_CERTIFICATE_CHAIN, respBytes));
      }
      case CMD_authz: {
        if (tokens.length != 2) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown authz", AuditLevel.ERROR, AuditStatus.FAILED);
        }

        AuthzId id = new AuthzId(Base64Url.decodeFast(tokens[1]));
        AcmeAuthz authz = repo.getAuthz(id);
        if (authz == null) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown authz", AuditLevel.ERROR, AuditStatus.FAILED);
        }

        if (LOG.isInfoEnabled()) {
          LOG.info("downloaded authz {}: {}", id, JSON.toJson(authz.toResponse(baseUrl, id.getOrderId())));
        }
        return buildSuccJsonResp(SC_OK, authz.toResponse(baseUrl, id.getOrderId()));
      }
      case CMD_chall: {
        if (tokens.length != 2) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown challenge", AuditLevel.ERROR, AuditStatus.FAILED);
        }

        ChallId challId = new ChallId(Base64Url.decodeFast(tokens[1]));
        AcmeChallenge2 chall2 = repo.getChallenge(challId);
        if (chall2 == null) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown challenge", AuditLevel.ERROR, AuditStatus.FAILED);
        }

        AcmeChallenge chall = chall2.getChallenge();

        ChallengeStatus status = chall.getStatus();
        if (status == ChallengeStatus.pending) {
          chall.setStatus(ChallengeStatus.processing);
        }
        ChallengeResponse resp = chall.toChallengeResponse(baseUrl, challId.getOrderId(), challId.getAuthzId());

        LOG.info("Received ready for challenge {} of order {}", challId, challId.getOrderId());
        RestResponse ret = buildSuccJsonResp(SC_OK, resp);//.putHeader(HDR_RETRY_AFTER, "2"); // wait for 2 seconds
        String authzUrl = chall2.getChallenge().authz().getUrl(baseUrl);
        ret.putHeader(HDR_LINK, "<" + authzUrl + ">;rel=\"up\"");
        return ret;
      }
      default: {
        throw new HttpRespAuditException(SC_NOT_FOUND, "unknown command " + command,
            AuditLevel.ERROR, AuditStatus.FAILED);
      }
    }
  } // method service

  private RestResponse toRestResponse(HttpRespContent respContent) {
    if (respContent == null) {
      return new RestResponse(SC_OK, null, null, null);
    } else {
      return new RestResponse(respContent.getStatusCode(), respContent.getContentType(), null,
          respContent.isBase64(), respContent.getContent());
    }
  }

  private AcmeOrder getOrder(String id) throws HttpRespAuditException, AcmeSystemException {
    Long lLabel = toLongId(id);
    AcmeOrder order = lLabel == null ? null : repo.getOrder(lLabel);
    if (order == null) {
      throw new HttpRespAuditException(SC_NOT_FOUND, "unknown order", AuditLevel.ERROR, AuditStatus.FAILED);
    }
    return order;
  }

  private RestResponse buildSuccJsonResp(int statusCode, Object body) {
    return toRestResponse(HttpRespContent.of(statusCode, CT_JSON, JSON.toJSONBytes(body)));
  }

  private RestResponse buildProblemResp(int statusCode, Problem problem) {
    byte[] bytes = JSON.toJSONBytes(problem);
    HttpRespContent content = HttpRespContent.of(statusCode, CT_PROBLEM_JSON, bytes);
    return toRestResponse(content);
  }

  private RestResponse verifySignature(PublicKey pubKey, JoseMessage joseMessage) throws AcmeProtocolException {
    try {
      JsonWebSignature jws = new JsonWebSignature();
      jws.setCompactSerialization(joseMessage.getProtected() + "." + joseMessage.getPayload()
          + "." + joseMessage.getSignature());
      jws.setKey(pubKey);
      boolean sigValid = jws.verifySignature();
      if (!sigValid) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "signature is not valid");
      }
      return null;
    } catch (InvalidAlgorithmException e) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.badSignatureAlgorithm, e.getMessage());
    } catch (JoseException e) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.malformed, "signature is not valid");
    }
  }

  private RestResponse verifyContacts(List<String> contacts) throws AcmeProtocolException {
    if (contacts == null || contacts.isEmpty()) {
      throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.invalidContact, "no contact is specified");
    }

    for (String contact : contacts) {
      int rc = contactVerifier.verfifyContact(contact);
      if (rc == ContactVerifier.unsupportedContact) {
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.unsupportedContact,
            "unsupported contact '" + contact + "'");
      } else if (rc == ContactVerifier.invalidContact){
        throw new AcmeProtocolException(SC_BAD_REQUEST, AcmeError.invalidContact,
            "invalid contact '" + contact + "'");
      }
    }
    return null;
  }

  private String rndToken() {
    byte[] token = new byte[tokenNumBytes];
    rnd.nextBytes(token);
    return Base64Url.encodeToStringNoPadding(token);
  }

  private AcmeChallenge newChall(int subId, String type, String token, String expectedAuthorization) {
    AcmeChallenge chall = new AcmeChallenge(subId, expectedAuthorization);
    chall.setStatus(ChallengeStatus.pending);
    chall.setType(type);
    chall.setToken(token);
    return chall;
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
      Instant certExpired = now.minus(cleanOrderConf.getExpiredCertDays(), ChronoUnit.DAYS);
      Instant notFinishedOrderExpires = now.minus(cleanOrderConf.getExpiredOrderDays(), ChronoUnit.DAYS);

      Thread thread = new Thread(() -> {
        try {
          int num = repo.cleanOrders(certExpired, notFinishedOrderExpires);
          LOG.info("removed {} orders with cert.notAfter<{} or not-finished-order.expires<{}",
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
    if (id.length() != 11) {
      return null;
    }
    return Pack.littleEndianToLong(Base64Url.decodeFast(id), 0);
  }

  private AcmeProxyConf.CaProfile getCaProfile(String keyAlgId) {
    for (AcmeProxyConf.CaProfile caProfile : caProfiles) {
      if (caProfile.getKeyTypes().contains(keyAlgId)) {
        return caProfile;
      }
    }

    return null;
  }

}
