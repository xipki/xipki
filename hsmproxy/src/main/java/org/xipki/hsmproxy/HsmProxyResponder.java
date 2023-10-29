// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.hsmproxy;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.MechanismInfo;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.*;
import org.xipki.security.pkcs11.hsmproxy.ProxyAction;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.*;
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
import java.util.*;

import static org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ProxyErrorCode.*;

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
    LOG.info("HSM PKCS#11 proxy version {}", StringUtil.getVersion(HsmProxyResponder.class));
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

        String msg = "module access path: https://<host>:<port>/hsmproxy/{}'";
        if ("default".equals(moduleName)) {
          msg += "and https://<host>:<port>/hsmproxy'";
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

    HttpResponse httpResp;
    try {
      httpResp = service(path, requestBytes, req);
    } catch (RuntimeException ex) {
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      httpResp = new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }

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
        String message = "found no module named " + moduleName;
        LOG.warn(message);
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
      }

      ProxyAction action = ProxyAction.ofNameIgnoreCase(command);

      if (action == null) {
        String message = "unknown action " + command;
        LOG.warn(message);
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
      }

      ProxyMessage respMessage;
      try {
        respMessage = processRequest(action, module, requestBytes);
      } catch (Exception ex) {
        LOG.debug("error while processing request", ex);
        if (ex instanceof PKCS11Exception) {
          respMessage = new ErrorResponse(pkcs11Exception,
              Long.toString(((PKCS11Exception) ex).getErrorCode()));
        } else if (ex instanceof TokenException) {
          respMessage = new ErrorResponse(tokenException, ex.getMessage());
        } else if (ex instanceof DecodeException) {
          respMessage = new ErrorResponse(badRequest, ex.getMessage());
        } else {
          respMessage = new ErrorResponse(internalError, ex.getMessage());
        }
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
          return failedHandles == null ? NULL_MESSAGE :  new LongArrayMessage(failedHandles);
        }
        case destroyObjectsByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          int numObjects = slot.destroyObjectsByIdLabel(req.getId(), req.getLabel());
          return new IntMessage(numObjects);
        }
        case genDSAKeypair:
        case genDSAKeypair2: // by key size
        case genECKeypair:
        case genRSAKeypair:
        case genSM2Keypair:
        case genSecretKey: {
          PKCS11KeyId generatedKeyId;
          switch (action) {
            case genDSAKeypair2: {
              GenerateDSAKeyPairByKeysizeRequest req = GenerateDSAKeyPairByKeysizeRequest.decode(reqDecoder);
              generatedKeyId = slot.generateDSAKeypair(req.getPlength(), req.getQlength(), req.getNewKeyControl());
              break;
            }
            case genDSAKeypair: {
              GenerateDSAKeyPairRequest req = GenerateDSAKeyPairRequest.decode(reqDecoder);
              generatedKeyId = slot.generateDSAKeypair(req.getP(), req.getQ(), req.getG(), req.getNewKeyControl());
              break;
            }
            case genECKeypair: {
              GenerateECKeyPairRequest req = GenerateECKeyPairRequest.decode(reqDecoder);
              generatedKeyId = slot.generateECKeypair(req.getCurveOid(), req.getNewKeyControl());
              break;
            }
            case genRSAKeypair: {
              GenerateRSAKeyPairRequest req = GenerateRSAKeyPairRequest.decode(reqDecoder);
              generatedKeyId = slot.generateRSAKeypair(
                                req.getKeySize(), req.getPublicExponent(), req.getNewKeyControl());
              break;
            }
            case genSM2Keypair: {
              GenerateSM2KeyPairRequest req = GenerateSM2KeyPairRequest.decode(reqDecoder);
              generatedKeyId = slot.generateSM2Keypair(req.getNewKeyControl());
              break;
            }
            default: { // case generateSecretKey
              GenerateSecretKeyRequest req = GenerateSecretKeyRequest.decode(reqDecoder);
              generatedKeyId = slot.generateSecretKey(req.getKeyType(), req.getKeySize(), req.getNewOKeyControl());
              break;
            }
          }

          return generatedKeyId == null ? NULL_MESSAGE :  new KeyIdMessage(generatedKeyId);
        }
        case genDSAKeypairOtf:
        case genECKeypairOtf:
        case genRSAKeypairOtf:
        case genSM2KeypairOtf: {
          PrivateKeyInfo privateKeyInfo;
          switch (action) {
            case genDSAKeypairOtf: {
              GenerateDSAKeyPairOtfRequest req = GenerateDSAKeyPairOtfRequest.decode(reqDecoder);
              privateKeyInfo = slot.generateDSAKeypairOtf(req.getP(), req.getQ(), req.getG());
              break;
            }
            case genECKeypairOtf: {
              GenerateECKeyPairOtfRequest req = GenerateECKeyPairOtfRequest.decode(reqDecoder);
              privateKeyInfo = slot.generateECKeypairOtf(req.getCurveOid());
              break;
            }
            case genRSAKeypairOtf: {
              GenerateRSAKeyPairOtfRequest req = GenerateRSAKeyPairOtfRequest.decode(reqDecoder);
              privateKeyInfo = slot.generateRSAKeypairOtf(req.getKeySize(), req.getPublicExponent());
              break;
            }
            default: { // case generateSM2KeypairOtf:
              reqDecoder.readNull();
              privateKeyInfo = slot.generateSM2KeypairOtf();
            }
          }

          return privateKeyInfo == null ? NULL_MESSAGE : new ByteArrayMessage(privateKeyInfo.getEncoded());
        }
        case keyByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          P11Key key = slot.getKey(req.getId(), req.getLabel());
          return key == null ? NULL_MESSAGE : new P11KeyResponse(key);
        }
        case keyByKeyId: {
          KeyIdMessage req = KeyIdMessage.decode(reqDecoder);
          P11Key key = slot.getKey(req.getKeyId());
          return key == null ? NULL_MESSAGE :  new P11KeyResponse(key);
        }
        case keyIdByIdLabel: {
          IdLabelMessage req = IdLabelMessage.decode(reqDecoder);
          PKCS11KeyId keyId = slot.getKeyId(req.getId(), req.getLabel());
          return keyId == null ? NULL_MESSAGE : new KeyIdMessage(keyId);
        }
        case mechInfos: {
          reqDecoder.readNull();
          Map<Long, MechanismInfo> mechanismInfoMap = slot.getMechanisms();
          return mechanismInfoMap == null ? NULL_MESSAGE : new GetMechanismInfosResponse(mechanismInfoMap);
        }
        case publicKeyByHandle: {
          LongMessage req = LongMessage.decode(reqDecoder);
          byte[] encodedPublicKey = slot.getPublicKey(req.getValue()).getEncoded();
          return encodedPublicKey == null ? NULL_MESSAGE : new ByteArrayMessage(encodedPublicKey);
        }
        case digestSecretKey: {
          DigestSecretKeyRequest req = DigestSecretKeyRequest.decode(reqDecoder);
          byte[] hashValue = slot.digestSecretKey(req.getMechanism(), req.getObjectHandle());
          return hashValue == null ? NULL_MESSAGE : new ByteArrayMessage(hashValue);
        }
        case sign: {
          SignRequest req = SignRequest.decode(reqDecoder);
          byte[] signatureValue = slot.sign(req.getMechanism(), req.getP11params(),
              req.getExtraParams(), req.getKeyHandle(), req.getContent());
          return signatureValue == null ? NULL_MESSAGE :  new ByteArrayMessage(signatureValue);
        }
        case importSecretKey: {
          ImportSecretKeyRequest req = ImportSecretKeyRequest.decode(reqDecoder);
          PKCS11KeyId keyId = slot.importSecretKey(req.getKeyType(), req.getKeyValue(), req.getNewKeyControl());
          return keyId == null ? NULL_MESSAGE :  new KeyIdMessage(keyId);
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

}
