// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.gateway.*;
import org.xipki.ca.gateway.acme.msg.*;
import org.xipki.ca.gateway.acme.type.*;
import org.xipki.ca.gateway.acme.util.AcmeJson;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.ca.sdk.*;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.*;
import org.xipki.util.*;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.HttpRespContent;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.StringUtil.*;
import static org.xipki.util.exception.ErrorCode.*;
import static org.xipki.util.Base64Url.decodeFast;
import static org.xipki.ca.gateway.acme.AcmeConstants.*;

/**
 * EST responder.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
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

  private final byte[] directoryBytes;

  private final String directoryHeader;

  private final String host;

  private final String host2;

  private final String baseUrl;

  private final String accountPrefix;

  private final String ca;

  private final String tlsProfile;

  private final SecureRandom rnd;

  private final AcmeRepo acmeRepo;

  private byte[] caSubject;

  private byte[][] cacerts;

  private final int tokenNumBytes;

  private final ChallengeValidator challengeValidator;

  private final CertEnroller certEnroller;

  static {
    knownCommands = CollectionUtil.asUnmodifiableSet(
        CMD_directory, CMD_newNonce, CMD_newAccount, CMD_newOrder, CMD_revokeCert, CMD_keyChange,
        CMD_account, CMD_order, CMD_orders, CMD_authz, CMD_chall, CMD_finalize, CMD_cert);
  }

  public AcmeResponder(SdkClient sdk, SecurityFactory securityFactory, PopControl popControl, AcmeProxyConf conf)
      throws InvalidConfException {
    this.sdk = notNull(sdk, "sdk");
    this.popControl = notNull(popControl, "popControl");
    this.securityFactory = notNull(securityFactory, "securityFactory");

    this.baseUrl = notBlank(conf.getBaseUrl(), "baseUrl");
    this.accountPrefix = this.baseUrl + "acct/";

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
    this.ca = conf.getCa();
    this.tlsProfile = conf.getTlsProfile();

    StringBuilder sb = new StringBuilder();
    sb.append("{");
    addJsonField(sb, "newNonce", baseUrl + CMD_newNonce);
    addJsonField(sb, "newAccount", baseUrl + CMD_newAccount);
    addJsonField(sb, "newOrder", baseUrl + CMD_newOrder);
    // newAuthz is not supported
    //addJsonField(sb, "newAuthz", baseUrl + CMD_newAuthz);
    addJsonField(sb, "revokeCert", baseUrl + CMD_revokeCert);
    addJsonField(sb, "keyChange", baseUrl + CMD_keyChange);

    sb.append(addQuoteSign("meta")).append(":{");
    if (StringUtil.isNotBlank(conf.getWebsite())) {
      addJsonField(sb, "website", conf.getWebsite());
    }

    if (StringUtil.isNotBlank(conf.getTermsOfService())) {
      addJsonField(sb, "termsOfService", conf.getTermsOfService());
    }

    if (conf.getCaaIdentities() != null && conf.getCaaIdentities().length > 0) {
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
    // TODO: use database
    acmeRepo = new InMemoryAcmeRepo();

    this.challengeValidator = new ChallengeValidator(acmeRepo);
    this.certEnroller = new CertEnroller(acmeRepo, sdk, ca);
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
    //t.setDaemon(true);
    t.start();

    t = new Thread(certEnroller);
    t.setName("certEnroller");
    //t.setDaemon(true);
    t.start();
  }

  public void close() {
    challengeValidator.close();
    certEnroller.close();
    nonceManager.destroy();
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
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }
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
      throws HttpRespAuditException, IOException, InvalidKeySpecException, JoseException, SdkErrorResponseException {
    String method = servletReq.getMethod();
    String path = servletReq.getServletPath();

    String ca = this.ca;

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
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed,
          "invalid Content-Type '" + contentType + "'");
    }

    JoseMessage body = JSON.parseObject(request, JoseMessage.class);
    AcmeJson protected_ = AcmeJson.parse(
        new ByteArrayInputStream(decodeFast(body.getProtected())));

    if (!protected_.contains("url")) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "url is not present");
    }

    String protectedUrl = protected_.get("url").asString();
    if (!protectedUrl.equals(baseUrl + path.substring(1))) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "url is not valid: '" + protectedUrl + "'");
    }

    if (!protected_.contains("nonce")) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.badNonce, "nonce is not present");
    }

    String nonce = protected_.get("nonce").asString();
    if (!nonceManager.removeNonce(nonce)) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.badNonce, null);
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
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed,
          "Both jwk and kid are specified, but exactly one of them is allowed");
    } else if (withJwk) {
      if ((verificationKeyRequirement & MASK_JWK) == 0) {
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed,
            "kid is specified, but jwk is allowed");
      }

      jwk = AcmeUtils.jsonToMap(protected_.get("jwk").asObject());
      try {
        pubKey = AcmeUtils.jwkPublicKey(jwk);
      } catch (Exception e) {
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.badPublicKey, null);
      }
    } else if (protected_.contains("kid")) {
      if ((verificationKeyRequirement & MASK_KID) == 0) {
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed,
            "jwk is specified, but kid is allowed");
      }

      // extract the location
      kid = protected_.get("kid").asString();
      if (kid.startsWith(accountPrefix)) {
        account = acmeRepo.getAccount(kid.substring(accountPrefix.length()));
      }

      if (account == null) {
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.accountDoesNotExist, null);
      }
      pubKey = account.getPublicKey();
    } else {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed,
          "None of jwk and kid is specified, but one of them is required");
    }

    // pre-check
    if (CMD_account.equals(command)) {
      if (protected_.get("url").asString().equals(kid)) {
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed,
            "kid and url do not match");
      }
    }

    // assert the account is valid
    if (account != null) {
      if (account.getStatus() != AccountStatus.valid) {
        return buildProblemResp(SC_UNAUTHORIZED, AcmeError.unauthorized,
            "account is not valid");
      }
    }

    boolean sigValid;
    try {
      sigValid = verifySignature(pubKey, body);
    } catch (InvalidAlgorithmException e) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.badSignatureAlgorithm, e.getMessage());
    }

    if (!sigValid) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "signature is not valid");
    }

    switch (command) {
      case CMD_newAccount: {
        NewAccountPayload reqPayload =
            JSON.parseObject(decodeFast(body.getPayload()), NewAccountPayload.class);

        AcmeAccount existingAccount = acmeRepo.getAccountForJwk(jwk);
        if (existingAccount != null) {
          return buildSuccJsonResp(SC_OK, existingAccount.toResponse(baseUrl))
              .putHeader(HDR_LOCATION, existingAccount.getLocation(baseUrl));
        }

        if (value(reqPayload.getOnlyReturnExisting(), false)) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.accountDoesNotExist, null);
        } else {
          // create a new account
          if (!value(reqPayload.getTermsOfServiceAgreed(), false)) {
            return buildProblemResp(SC_UNAUTHORIZED, AcmeError.userActionRequired,
                "terms of service has not been agreed");
          }

          AcmeAccount acmeAccount = new AcmeAccount();
          String[] contacts = reqPayload.getContact();
          if (contacts != null) {
            RestResponse verifyErrorResp = verifyContacts(contacts);
            if (verifyErrorResp != null) {
              return verifyErrorResp;
            }
            acmeAccount.setContact(contacts);
          }
          acmeAccount.setExternalAccountBinding(reqPayload.getExternalAccountBinding());
          acmeAccount.setTermsOfServiceAgreed(true);
          acmeAccount.setJwk(jwk);
          acmeAccount.setStatus(AccountStatus.valid);
          acmeRepo.addAccount(acmeAccount);

          AccountResponse resp = acmeAccount.toResponse(baseUrl);

          return buildSuccJsonResp(SC_CREATED, resp)
              .putHeader(HDR_LOCATION, acmeAccount.getLocation(baseUrl));
        }
      }
      case CMD_keyChange: {
        JoseMessage reqPayload = JSON.parseObject(decodeFast(body.getPayload()), JoseMessage.class);
        AcmeJson innerProtected = AcmeJson.parse(decodeFast(reqPayload.getProtected()));

        Map<String, String> newJwk = AcmeUtils.jsonToMap(innerProtected.get("jwk").asObject());
        AcmeAccount accountForNewJwk = acmeRepo.getAccountForJwk(newJwk);
        if (accountForNewJwk != null) {
          // jwk must not exist.
          return toRestResponse(HttpRespContent.of(SC_CONFLICT, null, null))
              .putHeader(HDR_LOCATION, accountForNewJwk.getLocation(baseUrl));
        }

        // check payload.account, and payload.oldKey
        AcmeJson innerPayload = AcmeJson.parse(decodeFast(reqPayload.getPayload()));
        String innerAccount = innerPayload.get("account").asString();
        if (!innerAccount.equals(kid)) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "invalid payload.account");
        }

        Map<String, String> oldKey = AcmeUtils.jsonToMap(innerPayload.get("oldKey").asObject());
        if (!account.hasJwk(oldKey)) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "oldKey does not match the account");
        }

        // check inner signature (by the new key)
        PublicKey newPubKey = AcmeUtils.jwkPublicKey(newJwk);
        boolean newSigValid = verifySignature(newPubKey, reqPayload);
        if (!newSigValid) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "inner signature is not valid");
        }

        account = acmeRepo.keyChange(account.getLabel(), newJwk);
        return buildSuccJsonResp(SC_OK, account.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, account.getLocation(baseUrl));
      }
      case CMD_account: {
        AccountResponse reqPayload = JSON.parseObject(decodeFast(body.getPayload()), AccountResponse.class);
        AccountStatus status = reqPayload.getStatus();
        if (status != null) {
          if (status == AccountStatus.deactivated) {
            // 7.3.6.  Account Deactivation
            account.setStatus(AccountStatus.deactivated);
          } else if (status == AccountStatus.revoked) {
            return buildProblemResp(SC_UNAUTHORIZED, AcmeError.unauthorized, "status revoked is not allowed");
          }
        }

        // 7.3.2.  Account Update
        String[] contacts = reqPayload.getContact();
        if (contacts != null && contacts.length > 0) {
          RestResponse errResp = verifyContacts(contacts);
          if (errResp != null) {
            return errResp;
          }

          account.setContact(contacts);
        }

        return buildSuccJsonResp(SC_OK, account.toResponse(baseUrl));
      }
      case CMD_revokeCert: {
        RevokeCertPayload reqPayload =
            JSON.parseObject(decodeFast(body.getPayload()), RevokeCertPayload.class);
        Integer reasonCode = reqPayload.getReason();
        CrlReason reason;
        try {
          reason = reasonCode == null ? CrlReason.UNSPECIFIED : CrlReason.forReasonCode(reasonCode);
        } catch (Exception e) {
          reason = null;
        }

        if (reason == null || !CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(reason)) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.badRevocationReason, null);
        }

        Certificate cert = Certificate.getInstance(decodeFast(reqPayload.getCertificate()));
        boolean jwkAndCertMatch;
        try {
          jwkAndCertMatch = AcmeUtils.matchKey(jwk, cert.getSubjectPublicKeyInfo());
        } catch (InvalidKeySpecException e) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.badPublicKey, "bad jwk");
        }
        if (!jwkAndCertMatch) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.unauthorized, "jwk and certificate do not match");
        }

        RevokeCertsRequest sdkReq = new RevokeCertsRequest();
        RevokeCertRequestEntry sdkEntry = new RevokeCertRequestEntry();
        sdkEntry.setReason(reason);
        sdkEntry.setSerialNumber(cert.getSerialNumber().getPositiveValue());
        sdkReq.setEntries(Collections.singletonList(sdkEntry));
        RevokeCertsResponse sdkResp = sdk.revokeCerts(ca, sdkReq);
        ErrorEntry errorEntry = sdkResp.getEntries().get(0).getError();
        if (errorEntry == null) {
          return buildSuccResp(SC_OK);
        } else {
          int errCode = errorEntry.getCode();
          if (errCode == ErrorCode.CERT_REVOKED.getCode()) {
            return buildProblemResp(SC_BAD_REQUEST, AcmeError.alreadyRevoked, null);
          } else if (errCode == UNKNOWN_CERT.getCode()) {
            return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "certificate is unknown");
          } else {
            return buildProblemResp(SC_FORBIDDEN, AcmeError.unauthorized, null);
          }
        }
      }
      case CMD_orders: {
        String label = tokens[1];
        if (!account.getLabel().equals(label)) {
          return buildProblemResp(SC_NOT_FOUND, null, null);
        }

        AcmeOrder[] orders = acmeRepo.getOrders(label);
        int size = orders == null ? 0 : orders.length;
        String[] urls = new String[size];
        for (int i = 0; i < size; i++) {
          urls[i] = baseUrl + "order/" + orders[i].getLabel();
        }
        OrdersResponse resp = new OrdersResponse();
        resp.setOrders(urls);
        return buildSuccJsonResp(SC_OK, resp);
      }
      case CMD_newOrder: {
        NewOrderPayload newOrderReq = JSON.parseObject(decodeFast(body.getPayload()), NewOrderPayload.class);
        Identifier[] identifiers = newOrderReq.getIdentifiers();
        int size = identifiers == null ? 0 : identifiers.length;

        if (size == 0) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.malformed, "no identifier is specified");
        }

        // 7 days validity
        Instant expires = Instant.now().plus(5, ChronoUnit.DAYS);

        AcmeAuthz[] authzs = new AcmeAuthz[size];
        for (int i = 0; i < size; i++) {
          AcmeAuthz authz = new AcmeAuthz();
          authzs[i] = authz;

          Identifier identifier = identifiers[i];
          authz.setIdentifier(identifier);
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
              return buildProblemResp(SC_BAD_REQUEST, AcmeError.unsupportedIdentifier,
                  "unsupported identifier '" + value + "'");
            }

            Map<String, String> jwk0 = account.getJwk();
            List<String> jwkNames = new ArrayList<>(jwk0.keySet());
            Collections.sort(jwkNames);
            StringBuilder canonJwk = new StringBuilder();
            canonJwk.append("{");
            for (String jwkName : jwkNames) {
              canonJwk.append("\"").append(jwkName).append("\":\"").append(jwk0.get(jwkName)).append("\",");
            }
            // remove the last ","
            canonJwk.deleteCharAt(canonJwk.length() - 1);
            canonJwk.append("}");
            String jwkSha256 = Base64Url.encodeToStringNoPadding(
                HashAlgo.SHA256.hash(canonJwk.toString().getBytes(StandardCharsets.UTF_8)));

            String authorization = token + "." + jwkSha256;
            String authorizationSha256 = Base64Url.encodeToStringNoPadding(
                HashAlgo.SHA256.hash(authorization.getBytes(StandardCharsets.UTF_8)));

            List<AcmeChallenge> challenges = new ArrayList<>(3);
            if (!value.startsWith("*.")) {
              challenges.add(newChall(HTTP_01, token, authorization));
              challenges.add(newChall(TLS_ALPN_01, token, authorizationSha256));
            }

            challenges.add(newChall(DNS_01, token, authorizationSha256));
            authz.setChallenges(challenges.toArray(new AcmeChallenge[0]));
          } else {
            return buildProblemResp(SC_BAD_REQUEST, AcmeError.unsupportedIdentifier,
                "unsupported identifier type '" + type + "'");
          }
        }

        AcmeOrder order = new AcmeOrder();
        if (newOrderReq.getNotBefore() != null) {
          order.setNotBefore(AcmeUtils.parseTimestamp(newOrderReq.getNotBefore()));
        }

        if (newOrderReq.getNotAfter() != null) {
          order.setNotAfter(AcmeUtils.parseTimestamp(newOrderReq.getNotAfter()));
        }

        order.setCertProfile(tlsProfile);
        order.setAuthzs(authzs);
        order.setExpires(expires);
        order.setAuthzs(authzs);

        acmeRepo.addOrder(account.getLabel(), order);

        return buildSuccJsonResp(SC_CREATED, order.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, order.getLocation(baseUrl));
      }
      case CMD_order: {
        String label = tokens[1];
        AcmeOrder order = getOrder(label);
        return buildSuccJsonResp(SC_CREATED, order.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, order.getLocation(baseUrl));
      }
      case CMD_finalize: {
        String label = tokens[1];
        AcmeOrder order = getOrder(label);
        if (order.getStatus() != OrderStatus.ready) {
          return buildProblemResp(SC_FORBIDDEN, AcmeError.orderNotReady, "order not ready");
        }

        FinalizeOrderPayload finalizeOrderReq = JSON.parseObject(decodeFast(body.getPayload()),
            FinalizeOrderPayload.class);

        byte[] csrBytes;
        CertificationRequest csr;
        try {
          csrBytes = Base64Url.decodeFast(finalizeOrderReq.getCsr());
          csr = CertificationRequest.getInstance(csrBytes);
        } catch (Exception e) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR, "could not parse CSR");
        }

        // verify the CSR
        Set<Identifier> identifiers = new HashSet<>();
        for (AcmeAuthz authz : order.getAuthzs()) {
          identifiers.add(authz.getIdentifier());
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
            return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR, "invalid commonName in CSR");
          }
        }

        Extensions csrExtensions = X509Util.getExtensions(csr.getCertificationRequestInfo());
        byte[] sanExtnValue = csrExtensions == null ? null
            : X509Util.getCoreExtValue(csrExtensions, Extension.subjectAlternativeName);
        if (sanExtnValue == null) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR, "no extension subjectAlternativeName in CSR");
        }

        GeneralNames generalNames = GeneralNames.getInstance(sanExtnValue);
        for (GeneralName gn : generalNames.getNames()) {
          int tagNo = gn.getTagNo();
          if (tagNo == GeneralName.dNSName) {
            String value = ASN1IA5String.getInstance(gn.getName()).getString();
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
              return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR,
                  "invalid DNS identifier in the extension subjectAlternativeName in CSR: " + value);
            }
          } else {
            return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR,
                "unsupported name in the extension subjectAlternativeName in CSR.");
          }
        }

        if (!identifiers.isEmpty()) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR,
              "missing identifier in the extension subjectAlternativeName in CSR: " + identifiers);
        }

        try {
          if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
            return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR, "could not verify signature of CSR");
          }
        } catch (Exception ex) {
          return buildProblemResp(SC_BAD_REQUEST, AcmeError.badCSR, ex.getMessage());
        }

        order.setCsr(csrBytes);
        order.setStatus(OrderStatus.processing);
        return buildSuccJsonResp(SC_OK, order.toResponse(baseUrl))
            .putHeader(HDR_LOCATION, order.getLocation(baseUrl));
      }
      case CMD_cert: {
        String label = tokens[1];
        AcmeOrder order = getOrder(label);
        byte[] certBytes = order.getCert();
        if (certBytes == null) {
          return buildProblemResp(SC_NOT_FOUND, AcmeError.orderNotReady, "found no certificate");
        }

        Certificate cert = Certificate.getInstance(certBytes);
        if (!Arrays.equals(cert.getIssuer().getEncoded(), caSubject)) {
          // TODO: extend SDK to retrieve cacerts according to X500Name: to cover case where ca
          // has changed the certificate meanwhile.
          cacerts = sdk.cacerts(ca);
        }

        byte[][] certchain = new byte[1 + cacerts.length][];
        certchain[0] = certBytes;
        System.arraycopy(cacerts, 0, certchain, 1, cacerts.length);

        byte[] respBytes = StringUtil.toUtf8Bytes(X509Util.encodeCertificates(certchain));
        return toRestResponse(HttpRespContent.ofOk(CT_PEM_CERTIFICATE_CHAIN, respBytes));
      }
      case CMD_authz: {
        if (tokens.length != 2) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown authz", AuditLevel.ERROR, AuditStatus.FAILED);
        }

        String label = tokens[1];
        AcmeAuthz authz = acmeRepo.getAuthz(label);
        if (authz == null) {
          throw new HttpRespAuditException(SC_NOT_FOUND, "unknown authz", AuditLevel.ERROR, AuditStatus.FAILED);
        }
        return buildSuccJsonResp(SC_OK, authz.toResponse(baseUrl));
      }
      case CMD_chall: {
        String label = tokens[1];
        AcmeChallenge chall = acmeRepo.getChallenge(label);
        ChallengeStatus status = chall.getStatus();
        if (status == ChallengeStatus.pending) {
          chall.setStatus(ChallengeStatus.processing);
        }
        ChallengeResponse resp = chall.toChallengeResponse(baseUrl);
        resp.setUrl(baseUrl + "chall/" + label);
        return buildSuccJsonResp(SC_OK, resp);//.putHeader(HDR_RETRY_AFTER, "2"); // wait for 2 seconds
      }
      default: {
        throw new HttpRespAuditException(SC_NOT_FOUND, "unknown command " + command,
            AuditLevel.ERROR, AuditStatus.FAILED);
      }
    }
  } // method service

  private static boolean value(Boolean v, boolean dflt) {
    return v == null ? dflt : v.booleanValue();
  }

  private RestResponse toRestResponse(HttpRespContent respContent) {
    if (respContent == null) {
      return new RestResponse(SC_OK, null, null, null);
    } else {
      return new RestResponse(respContent.getStatusCode(), respContent.getContentType(), null,
          respContent.isBase64(), respContent.getContent());
    }
  }

  private AcmeOrder getOrder(String label) throws HttpRespAuditException {
    AcmeOrder order = acmeRepo.getOrder(label);
    if (order == null) {
      throw new HttpRespAuditException(SC_NOT_FOUND, "unknown order", AuditLevel.ERROR, AuditStatus.FAILED);
    }
    return order;
  }

  private RestResponse buildProblemResp(int statusCode, String type, String detail) {
    Problem problem = new Problem();
    problem.setType(type);
    problem.setDetail(detail);
    return buildProblemResp(statusCode, problem);
  }

  private RestResponse buildSuccJsonResp(int statusCode, Object body) {
    return toRestResponse(HttpRespContent.of(statusCode, CT_JSON, JSON.toJSONBytes(body)));
  }

  private RestResponse buildSuccResp(int statusCode) {
    return toRestResponse(HttpRespContent.of(statusCode, null, null));
  }

  private RestResponse buildProblemResp(int statusCode, Problem problem) {
    byte[] bytes = JSON.toJSONBytes(problem);
    HttpRespContent content = HttpRespContent.of(statusCode, CT_PROBLEM_JSON, bytes);
    return toRestResponse(content);
  }

  private boolean verifySignature(PublicKey pubKey, JoseMessage joseMessage) throws JoseException {
    JsonWebSignature jws = new JsonWebSignature();
    jws.setCompactSerialization(joseMessage.getProtected() + "." + joseMessage.getPayload()
        + "." + joseMessage.getSignature());
    jws.setKey(pubKey);
    return jws.verifySignature();
  }

  private RestResponse verifyContacts(String[] contacts) {
    if (contacts == null || contacts.length == 0) {
      return buildProblemResp(SC_BAD_REQUEST, AcmeError.invalidContact, "no contact is specified");
    }

    for (String contact : contacts) {
      int rc = contactVerifier.verfifyContact(contact);
      if (rc == ContactVerifier.unsupportedContact) {
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.unsupportedContact,
            "unsupported contact '" + contact + "'");
      } else if (rc == ContactVerifier.invalidContact){
        return buildProblemResp(SC_BAD_REQUEST, AcmeError.invalidContact,
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

  private AcmeChallenge newChall(String type, String token, String expectedAuthorization) {
    AcmeChallenge chall = new AcmeChallenge();
    chall.setStatus(ChallengeStatus.pending);
    chall.setType(type);
    chall.setToken(token);
    chall.setExpectedAuthorization(expectedAuthorization);
    LOG.info("challenge: {}:{}={}", type, token, expectedAuthorization);
    return chall;
  }

}
