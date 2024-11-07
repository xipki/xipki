// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.hsmproxy;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.MechanismInfo;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Key;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ModuleConf;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.security.pkcs11.hsmproxy.ProxyAction;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.BooleanMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ByteArrayMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.DigestSecretKeyRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ErrorResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateDSAKeyPairByKeysizeRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateDSAKeyPairOtfRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateDSAKeyPairRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateECKeyPairOtfRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateECKeyPairRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateRSAKeyPairOtfRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateRSAKeyPairRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateSM2KeyPairRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GenerateSecretKeyRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GetMechanismInfosResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.IdLabelMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ImportSecretKeyRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.IntMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.KeyIdMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.LongArrayMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.LongMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ModuleCapsResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.P11KeyResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ShowDetailsRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.SignRequest;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.SlotIdsResponse;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.ByteArrayCborEncoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ProxyErrorCode.badRequest;

/**
 * The responder of HSM proxy.
 *
 * @author Lijun Liao (xipki)
 */

public class HsmProxyResponder {

  private static final Logger LOG = LoggerFactory.getLogger(HsmProxyResponder.class);

  private static final String REQUEST_MIMETYPE = "application/x-xipki-pkcs11";

  private static final String RESPONSE_MIMETYPE = "application/x-xipki-pkcs11";

  private static final ProxyMessage NULL_MESSAGE = new ProxyMessage() {
    @Override
    protected void encode0(CborEncoder encoder) throws IOException {
      encoder.writeNull();
    }
  };

  private final Map<String, P11Module> modules = new HashMap<>();

  private final boolean logReqResp;

  private final String reverseProxyMode;

  private final Set<X509Cert> clientCerts;

  static {
    LOG.info("HSM PKCS#11 proxy version {}", StringUtil.getBundleVersion(HsmProxyResponder.class));
  }

  public HsmProxyResponder(boolean logReqResp, String reverseProxyMode,
                           P11CryptServiceFactory p11CryptServiceFactory,
                           Collection<X509Cert> clientCerts)
      throws XiSecurityException, TokenException {
    this.logReqResp = logReqResp;
    this.reverseProxyMode = reverseProxyMode;
    this.clientCerts = new HashSet<>(Args.notEmpty(clientCerts, "clientCerts"));
    Args.notNull(p11CryptServiceFactory, "p11CryptServiceFactory");
    Set<String> moduleNames = p11CryptServiceFactory.getModuleNames();
    for (String moduleName : moduleNames) {
      moduleName = moduleName.toLowerCase(Locale.ROOT);
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service != null) {
        if (modules.containsKey(moduleName)) {
          throw new XiSecurityException("module for name " + moduleName
              + " already used, use another module name");
        }
        modules.put(moduleName, p11Service.getModule());

        String msg = "module access path: 'https://<host>:<port>/hp/{}'";
        if ("default".equals(moduleName)) {
          msg += " or 'https://<host>:<port>/hp'";
        }
        LOG.info(msg, moduleName);
      }
    }
  }

  public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String method = req.getMethod();
    if (!"POST".equalsIgnoreCase(method)) {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
      return;
    }

    X509Cert clientCert = TlsHelper.getTlsClientCert(req, reverseProxyMode);
    if (clientCert == null || !clientCerts.contains(clientCert)) {
      resp.setStatus(HttpStatusCode.SC_UNAUTHORIZED);
      return;
    }

    String path = req.getServletPath();
    byte[] requestBytes = IoUtil.readAllBytes(req.getInputStream());
    HttpResponse httpResp = service(path, requestBytes, req);
    LogUtil.logReqResp("REST Gateway path=" + req.getServletPath(), LOG, logReqResp,
        true, req.getRequestURI(), requestBytes, httpResp.getBody());
    httpResp.fillResponse(resp);
  }

  public HttpResponse service(String path, byte[] requestBytes, XiHttpRequest request) {
    byte[] responseBytes;

    try {
      String reqContentType = request.getHeader("Content-Type");
      if (!REQUEST_MIMETYPE.equalsIgnoreCase(reqContentType)) {
        return new HttpResponse(HttpStatusCode.SC_UNSUPPORTED_MEDIA_TYPE);
      }

      String moduleName;
      String command;

      // the first char is always '/'
      String coreUri = path.substring(1);
      String[] tokens = StringUtil.splitAsArray(coreUri, "/");
      if (tokens.length == 1) {
        moduleName = "default";
        command = tokens[0];
      } else if (tokens.length == 2) {
        moduleName = tokens[0];
        command = tokens[1];
      } else {
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
      }

      P11Module module = modules.get(moduleName);
      if (module == null) {
        LOG.warn("found no module named {}", moduleName);
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
      }

      ProxyAction action = ProxyAction.ofNameIgnoreCase(command);

      if (action == null) {
        LOG.warn("unknown action {}", command);
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
      }

      ProxyMessage respMessage;
      try {
        respMessage = processRequest(action, module, requestBytes);
      } catch (Exception ex) {
        LOG.debug("error while processing request", ex);
        respMessage = new ErrorResponse(ex);
      }

      ByteArrayCborEncoder cborEncoder = new ByteArrayCborEncoder();

      if (respMessage instanceof ErrorResponse) {
        cborEncoder.writeTag(ErrorResponse.CBOR_TAG_ERROR_RESPONSE);
        ErrorResponse errorResponse = (ErrorResponse) respMessage;
        LOG.warn("{} FAILED with {}: {}", action, errorResponse.getErrorCode(), errorResponse.getDetail());
      } else {
        LOG.info("{} SUCCESSFUL", action);
      }

      respMessage.encode(cborEncoder);
      responseBytes = cborEncoder.toByteArray();
      return new HttpResponse(HttpStatusCode.SC_OK, RESPONSE_MIMETYPE, null, responseBytes);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "Connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private ProxyMessage processRequest(ProxyAction action, P11Module module, byte[] reqBytes)
      throws TokenException, DecodeException, IOException {
    Args.notNull(action, "action");
    Args.notNull(module, "module");
    Args.notNull(reqBytes, "reqBytes");

    try (CborDecoder reqDecoder = new ByteArrayCborDecoder(reqBytes)) {
      if (reqDecoder.readNullOrArrayLength(2)) {
        return new ErrorResponse(badRequest, "request shall not be a CBOR null.");
      }

      Long id;
      try {
        id = reqDecoder.readLongObj();
      } catch (IOException e) {
        return new ErrorResponse(badRequest, e.getMessage());
      }

      // actions do not need slot.
      if (action == ProxyAction.moduleCaps) {
        reqDecoder.readNull();
        P11ModuleConf mc = module.getConf();
        return new ModuleCapsResponse(module.isReadOnly(), mc.getMaxMessageSize(),
            mc.getP11NewObjectConf(), mc.getSecretKeyTypes(), mc.getKeyPairTypes());
      } else if (action == ProxyAction.slotIds) {
        reqDecoder.readNull();
        List<P11SlotId> slotIds = module.getSlotIds();
        return new SlotIdsResponse(slotIds);
      }

      if (id == null) {
        return new ErrorResponse(badRequest, "no slot specified");
      }

      P11SlotId slotId = module.getSlotIdForId(id);
      if (slotId == null) {
        return new ErrorResponse(badRequest, "unknown slot id " + id);
      }

      P11Slot slot = module.getSlot(slotId);
      if (slot == null) {
        return new ErrorResponse(badRequest, "error finding slot for id " + id);
      }

      switch (action) {
        case destroyAllObjects: {
          reqDecoder.readNull();
          int numObjects = slot.destroyAllObjects();
          return new IntMessage(numObjects);
        }
        case destroyObjectsByHandle: {
          LongArrayMessage req = LongArrayMessage.decode(reqDecoder);
          long[] failedHandles = slot.destroyObjectsByHandle(req.getValue());
          return failedHandles == null ? NULL_MESSAGE : new LongArrayMessage(failedHandles);
        }
        case destroyObjectsByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          int numObjects = slot.destroyObjectsByIdLabel(req.getId(), req.getLabel());
          return new IntMessage(numObjects);
        }
        case genDSAKeypair: {
          GenerateDSAKeyPairRequest req = GenerateDSAKeyPairRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateDSAKeypair(req.getP(), req.getQ(), req.getG(), req.getNewKeyControl()));
        }
        case genDSAKeypair2: { // by key size
          GenerateDSAKeyPairByKeysizeRequest req = GenerateDSAKeyPairByKeysizeRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateDSAKeypair(req.getPlength(), req.getQlength(), req.getNewKeyControl()));
        }
        case genECKeypair: {
          GenerateECKeyPairRequest req = GenerateECKeyPairRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateECKeypair(req.getCurveOid(), req.getNewKeyControl()));
        }
        case genRSAKeypair: {
          GenerateRSAKeyPairRequest req = GenerateRSAKeyPairRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateRSAKeypair(req.getKeySize(), req.getPublicExponent(), req.getNewKeyControl()));
        }
        case genSM2Keypair: {
          GenerateSM2KeyPairRequest req = GenerateSM2KeyPairRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateSM2Keypair(req.getNewKeyControl()));
        }
        case genSecretKey: {
          GenerateSecretKeyRequest req = GenerateSecretKeyRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateSecretKey(req.getKeyType(), req.getKeySize(), req.getNewOKeyControl()));
        }
        case genDSAKeypairOtf: {
          GenerateDSAKeyPairOtfRequest req = GenerateDSAKeyPairOtfRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateDSAKeypairOtf(req.getP(), req.getQ(), req.getG()));
        }
        case genECKeypairOtf: {
          GenerateECKeyPairOtfRequest req = GenerateECKeyPairOtfRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateECKeypairOtf(req.getCurveOid()));
        }
        case genRSAKeypairOtf: {
          GenerateRSAKeyPairOtfRequest req = GenerateRSAKeyPairOtfRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.generateRSAKeypairOtf(req.getKeySize(), req.getPublicExponent()));
        }
        case genSM2KeypairOtf: {
          reqDecoder.readNull();
          return toProxyMessage(
              slot.generateSM2KeypairOtf());
        }
        case keyByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          return toProxyMessage(
              slot.getKey(req.getId(), req.getLabel()));
        }
        case keyByKeyId: {
          KeyIdMessage req = KeyIdMessage.decode(reqDecoder);
          return toProxyMessage(
              slot.getKey(req.getKeyId()));
        }
        case keyIdByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          return toProxyMessage(
              slot.getKeyId(req.getId(), req.getLabel()));
        }
        case mechInfos: {
          reqDecoder.readNull();
          Map<Long, MechanismInfo> mechanismInfoMap = slot.getMechanisms();
          return mechanismInfoMap == null ? NULL_MESSAGE : new GetMechanismInfosResponse(mechanismInfoMap);
        }
        case publicKeyByHandle: {
          LongMessage req = LongMessage.decode(reqDecoder);
          return toProxyMessage(
              slot.getPublicKey(req.getValue()).getEncoded());
        }
        case digestSecretKey: {
          DigestSecretKeyRequest req = DigestSecretKeyRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.digestSecretKey(req.getMechanism(), req.getObjectHandle()));
        }
        case sign: {
          SignRequest req = SignRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.sign(req.getMechanism(), req.getP11params(),
                req.getExtraParams(), req.getKeyHandle(), req.getContent()));
        }
        case importSecretKey: {
          ImportSecretKeyRequest req = ImportSecretKeyRequest.decode(reqDecoder);
          return toProxyMessage(
              slot.importSecretKey(req.getKeyType(), req.getKeyValue(), req.getNewKeyControl()));
        }
        case objectExistsByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          boolean exists = slot.objectExistsByIdLabel(req.getId(), req.getLabel());
          return new BooleanMessage(exists);
        }
        case showDetails: {
          ShowDetailsRequest req = ShowDetailsRequest.decode(reqDecoder);
          ByteArrayOutputStream bout = new ByteArrayOutputStream(2048);
          try {
            slot.showDetails(bout, req.getObjectHandle(), req.isVerbose());
          } catch (IOException ex) {
            throw new TokenException(ex);
          }
          byte[] bytes = bout.toByteArray();
          return new ByteArrayMessage(bytes);
        }
        default: {
          throw new IllegalStateException("unknown command " + action);
        }
      }
    }
  }

  private static ProxyMessage toProxyMessage(PKCS11KeyId keyId) {
    return keyId == null ? NULL_MESSAGE : new KeyIdMessage(keyId);
  }

  private static ProxyMessage toProxyMessage(P11Key key) {
    return key == null ? NULL_MESSAGE : new P11KeyResponse(key);
  }

  private static ProxyMessage toProxyMessage(PrivateKeyInfo key) throws IOException {
    return key == null ? NULL_MESSAGE : new ByteArrayMessage(key.getEncoded());
  }

  private static ProxyMessage toProxyMessage(byte[] bytes) {
    return bytes == null ? NULL_MESSAGE : new ByteArrayMessage(bytes);
  }

}
