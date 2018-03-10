/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.p11proxy.server;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.Hex;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.p11proxy.P11ProxyConstants;
import org.xipki.p11proxy.msg.Asn1DigestSecretKeyTemplate;
import org.xipki.p11proxy.msg.Asn1EntityIdAndCert;
import org.xipki.p11proxy.msg.Asn1GenDSAKeypairParams;
import org.xipki.p11proxy.msg.Asn1GenECKeypairParams;
import org.xipki.p11proxy.msg.Asn1GenRSAKeypairParams;
import org.xipki.p11proxy.msg.Asn1GenSM2KeypairParams;
import org.xipki.p11proxy.msg.Asn1GenSecretKeyParams;
import org.xipki.p11proxy.msg.Asn1ImportSecretKeyParams;
import org.xipki.p11proxy.msg.Asn1P11EntityIdentifier;
import org.xipki.p11proxy.msg.Asn1P11ObjectIdentifier;
import org.xipki.p11proxy.msg.Asn1P11Params;
import org.xipki.p11proxy.msg.Asn1P11SlotIdentifier;
import org.xipki.p11proxy.msg.Asn1RSAPkcsPssParams;
import org.xipki.p11proxy.msg.Asn1RemoveObjectsParams;
import org.xipki.p11proxy.msg.Asn1ServerCaps;
import org.xipki.p11proxy.msg.Asn1SignTemplate;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.exception.P11DuplicateEntityException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.P11UnknownEntityException;
import org.xipki.security.exception.P11UnsupportedMechanismException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11EntityIdentifier;
import org.xipki.security.pkcs11.P11IVParams;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class P11ProxyResponder {
  private static final Logger LOG = LoggerFactory.getLogger(P11ProxyResponder.class);

  private static final Set<Short> actionsRequireNonNullRequest;

  private static final Set<Short> actionsRequireNullRequest;

  private final Set<Short> versions;

  static {
    Set<Short> actions = new HashSet<>();
    actions.add(P11ProxyConstants.ACTION_GET_SERVER_CAPS);
    actions.add(P11ProxyConstants.ACTION_GET_SLOT_IDS);
    actionsRequireNullRequest = Collections.unmodifiableSet(actions);

    actions = new HashSet<>();
    actions.add(P11ProxyConstants.ACTION_ADD_CERT);
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_DSA);
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_EC);
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_RSA);
    actions.add(P11ProxyConstants.ACTION_GEN_SECRET_KEY);
    actions.add(P11ProxyConstants.ACTION_IMPORT_SECRET_KEY);

    actions.add(P11ProxyConstants.ACTION_GET_CERT);
    actions.add(P11ProxyConstants.ACTION_GET_CERT_IDS);
    actions.add(P11ProxyConstants.ACTION_GET_IDENTITY_IDS);
    actions.add(P11ProxyConstants.ACTION_GET_MECHANISMS);
    actions.add(P11ProxyConstants.ACTION_GET_PUBLICKEY);
    actions.add(P11ProxyConstants.ACTION_REMOVE_CERTS);
    actions.add(P11ProxyConstants.ACTION_REMOVE_IDENTITY);
    actions.add(P11ProxyConstants.ACTION_REMOVE_OBJECTS);
    actions.add(P11ProxyConstants.ACTION_SIGN);
    actions.add(P11ProxyConstants.ACTION_UPDATE_CERT);
    actions.add(P11ProxyConstants.ACTION_DIGEST_SECRETKEY);
    actions.add(P11ProxyConstants.ACTION_IMPORT_SECRET_KEY);
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_SM2);
    actionsRequireNonNullRequest = Collections.unmodifiableSet(actions);
  }

  P11ProxyResponder() {
    Set<Short> tmpVersions = new HashSet<>();
    tmpVersions.add(P11ProxyConstants.VERSION_V1_0);
    this.versions = Collections.unmodifiableSet(tmpVersions);
  }

  public Set<Short> versions() {
    return versions;
  }

  /**
   * The request is constructed as follows:
   * <pre>
   * 0 - - - 1 - - - 2 - - - 3 - - - 4 - - - 5 - - - 6 - - - 7 - - - 8
   * |    Version    |        Transaction ID         |   Body ...    |
   * |   ... Length  |     Action    |   Module ID   |   Content...  |
   * |   .Content               | <-- 10 + Length (offset).
   *
   * </pre>
   */
  byte[] processRequest(LocalP11CryptServicePool pool, byte[] request) {
    int reqLen = request.length;

    // TransactionID
    byte[] transactionId = new byte[4];
    if (reqLen > 5) {
      System.arraycopy(request, 2, transactionId, 0, 4);
    }

    // Action
    short action = P11ProxyConstants.ACTION_NOPE;
    if (reqLen > 11) {
      action = IoUtil.parseShort(request, 10);
    }

    if (reqLen < 14) {
      LOG.error("response too short");
      return getResp(P11ProxyConstants.VERSION_V1_0, transactionId, action,
          P11ProxyConstants.RC_BAD_REQUEST);
    }

    // Version
    short version = IoUtil.parseShort(request, 0);
    if (!versions.contains(version)) {
      LOG.error("unsupported version {}", version);
      return getResp(P11ProxyConstants.VERSION_V1_0, transactionId, action,
          P11ProxyConstants.RC_UNSUPPORTED_VERSION);
    }

    // Length
    int reqBodyLen = IoUtil.parseInt(request, 6);
    if (reqBodyLen + 10 != reqLen) {
      LOG.error("message length unmatch");
      return getResp(version, transactionId, action, P11ProxyConstants.RC_BAD_REQUEST);
    }

    short moduleId = IoUtil.parseShort(request, 12);

    int contentLen = reqLen - 14;
    byte[] content;
    if (contentLen == 0) {
      if (actionsRequireNonNullRequest.contains(action)) {
        LOG.error("content is not present but is required");
        return getResp(version, transactionId, P11ProxyConstants.RC_BAD_REQUEST, action);
      }
      content = null;
    } else {
      if (actionsRequireNullRequest.contains(action)) {
        LOG.error("content is present but is not permitted");
        return getResp(version, transactionId, P11ProxyConstants.RC_BAD_REQUEST, action);
      }

      content = new byte[contentLen];
      System.arraycopy(request, 14, content, 0, contentLen);
    }

    P11CryptService p11CryptService = pool.getP11CryptService(moduleId);
    if (p11CryptService == null) {
      LOG.error("no module {} available", moduleId);
      return getResp(version, transactionId, P11ProxyConstants.RC_UNKNOWN_MODULE, action);
    }

    try {
      switch (action) {
        case P11ProxyConstants.ACTION_ADD_CERT: {
          Asn1EntityIdAndCert asn1 = Asn1EntityIdAndCert.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.entityId());
          X509Certificate cert = X509Util.toX509Cert(asn1.certificate());
          slot.addCert(asn1.entityId().objectId().objectId(), cert);
          return getSuccessResp(version, transactionId, action, (byte[]) null);
        }
        case P11ProxyConstants.ACTION_DIGEST_SECRETKEY: {
          Asn1DigestSecretKeyTemplate template = Asn1DigestSecretKeyTemplate.getInstance(content);
          long mechanism = template.mechanism().mechanism();
          P11Identity identity = p11CryptService.getIdentity(template.identityId().entityId());
          byte[] hashValue = identity.digestSecretKey(mechanism);
          ASN1Object obj = new DEROctetString(hashValue);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_DSA: {
          Asn1GenDSAKeypairParams asn1 = Asn1GenDSAKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          P11ObjectIdentifier keyId = slot.generateDSAKeypair(asn1.p(), asn1.q(), asn1.g(),
              asn1.label(), asn1.control());
          ASN1Object obj = new Asn1P11EntityIdentifier(asn1.slotId(), keyId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_EC: {
          Asn1GenECKeypairParams asn1 = Asn1GenECKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          P11ObjectIdentifier keyId = slot.generateECKeypair(asn1.curveId().getId(),
              asn1.label(), asn1.control());
          ASN1Object obj = new Asn1P11EntityIdentifier(asn1.slotId(), keyId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_RSA: {
          Asn1GenRSAKeypairParams asn1 = Asn1GenRSAKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          P11ObjectIdentifier keyId = slot.generateRSAKeypair(asn1.keysize(),
              asn1.publicExponent(), asn1.label(), asn1.control());
          ASN1Object obj = new Asn1P11EntityIdentifier(asn1.slotId(), keyId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_SM2: {
          Asn1GenSM2KeypairParams asn1 = Asn1GenSM2KeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          P11ObjectIdentifier keyId = slot.generateSM2Keypair(asn1.label(), asn1.control());
          ASN1Object obj = new Asn1P11EntityIdentifier(asn1.slotId(), keyId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_SECRET_KEY: {
          Asn1GenSecretKeyParams asn1 = Asn1GenSecretKeyParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          P11ObjectIdentifier keyId = slot.generateSecretKey(asn1.keyType(), asn1.keysize(),
              asn1.label(), asn1.control());
          ASN1Object obj = new Asn1P11EntityIdentifier(asn1.slotId(), keyId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_CERT: {
          P11EntityIdentifier entityId = Asn1P11EntityIdentifier.getInstance(content).entityId();
          X509Certificate cert = p11CryptService.getIdentity(entityId).certificate();
          return getSuccessResp(version, transactionId, action, cert.getEncoded());
        }
        case P11ProxyConstants.ACTION_GET_CERT_IDS:
        case P11ProxyConstants.ACTION_GET_IDENTITY_IDS: {
          Asn1P11SlotIdentifier slotId = Asn1P11SlotIdentifier.getInstance(content);
          P11Slot slot = p11CryptService.module().getSlot(slotId.slotId());
          Set<P11ObjectIdentifier> objectIds;
          if (P11ProxyConstants.ACTION_GET_CERT_IDS == action) {
            objectIds = slot.certIdentifiers();
          } else {
            objectIds = slot.identityIdentifiers();
          }
          ASN1EncodableVector vec = new ASN1EncodableVector();
          for (P11ObjectIdentifier objectId : objectIds) {
            vec.add(new Asn1P11ObjectIdentifier(objectId));
          }
          ASN1Object obj = new DERSequence(vec);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_MECHANISMS: {
          P11SlotIdentifier slotId = Asn1P11SlotIdentifier.getInstance(content).slotId();
          Set<Long> mechs = p11CryptService.getSlot(slotId).mechanisms();
          ASN1EncodableVector vec = new ASN1EncodableVector();
          for (Long mech : mechs) {
            vec.add(new ASN1Integer(mech));
          }
          ASN1Object obj = new DERSequence(vec);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_PUBLICKEY: {
          P11EntityIdentifier identityId = Asn1P11EntityIdentifier.getInstance(content).entityId();
          PublicKey pubKey = p11CryptService.getIdentity(identityId).publicKey();
          if (pubKey == null) {
            throw new P11UnknownEntityException(identityId);
          }

          ASN1Object obj = KeyUtil.createSubjectPublicKeyInfo(pubKey);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_SERVER_CAPS: {
          boolean readOnly = p11CryptService.module().isReadOnly();
          ASN1Object obj = new Asn1ServerCaps(readOnly, versions);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_SLOT_IDS: {
          List<P11SlotIdentifier> slotIds = p11CryptService.module().slotIdentifiers();

          ASN1EncodableVector vector = new ASN1EncodableVector();
          for (P11SlotIdentifier slotId : slotIds) {
            vector.add(new Asn1P11SlotIdentifier(slotId));
          }
          ASN1Object obj = new DERSequence(vector);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_IMPORT_SECRET_KEY: {
          Asn1ImportSecretKeyParams asn1 = Asn1ImportSecretKeyParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          P11ObjectIdentifier keyId = slot.importSecretKey(asn1.keyType(),
              asn1.keyValue(), asn1.label(), asn1.control());
          ASN1Object obj = new Asn1P11EntityIdentifier(asn1.slotId(), keyId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_REMOVE_CERTS: {
          Asn1P11EntityIdentifier asn1 = Asn1P11EntityIdentifier.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1);
          slot.removeCerts(asn1.objectId().objectId());
          return getSuccessResp(version, transactionId, action, (byte[])null);
        }
        case P11ProxyConstants.ACTION_REMOVE_IDENTITY: {
          Asn1P11EntityIdentifier asn1 = Asn1P11EntityIdentifier.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1);
          slot.removeIdentity(asn1.objectId().objectId());
          return getSuccessResp(version, transactionId, action, (byte[])null);
        }
        case P11ProxyConstants.ACTION_REMOVE_OBJECTS: {
          Asn1RemoveObjectsParams asn1 = Asn1RemoveObjectsParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.slotId());
          int num = slot.removeObjects(asn1.ojectId(), asn1.objectLabel());
          ASN1Object obj = new ASN1Integer(num);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_SIGN: {
          Asn1SignTemplate signTemplate = Asn1SignTemplate.getInstance(content);
          long mechanism = signTemplate.mechanism().mechanism();
          Asn1P11Params asn1Params = signTemplate.mechanism().params();

          P11Params params = null;

          if (asn1Params != null) {
            switch (asn1Params.tagNo()) {
              case Asn1P11Params.TAG_RSA_PKCS_PSS:
                params = Asn1RSAPkcsPssParams.getInstance(asn1Params).pkcsPssParams();
                break;
              case Asn1P11Params.TAG_OPAQUE:
                params = new P11ByteArrayParams(
                    ASN1OctetString.getInstance(asn1Params).getOctets());
                break;
              case Asn1P11Params.TAG_IV:
                params = new P11IVParams(ASN1OctetString.getInstance(asn1Params).getOctets());
                break;
              default:
                throw new BadAsn1ObjectException(
                    "unknown SignTemplate.params: unknown tag " + asn1Params.tagNo());
            }
          }

          byte[] message = signTemplate.message();
          P11Identity identity = p11CryptService.getIdentity(signTemplate.identityId().entityId());
          byte[] signature = identity.sign(mechanism, params, message);
          ASN1Object obj = new DEROctetString(signature);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_UPDATE_CERT: {
          Asn1EntityIdAndCert asn1 = Asn1EntityIdAndCert.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.entityId());
          slot.updateCertificate(asn1.entityId().objectId().objectId(),
              X509Util.toX509Cert(asn1.certificate()));
          return getSuccessResp(version, transactionId, action, (byte[])null);
        }
        default: {
          LOG.error("unsupported XiPKI action code '{}'", action);
          return getResp(version, transactionId, action, P11ProxyConstants.RC_UNSUPPORTED_ACTION);
        }
      }
    } catch (BadAsn1ObjectException ex) {
      LogUtil.error(LOG, ex, "could not process decode requested content (tid="
          + Hex.encode(transactionId) + ")");
      return getResp(version, transactionId, action, P11ProxyConstants.RC_BAD_REQUEST);
    } catch (P11TokenException ex) {
      LogUtil.error(LOG, ex, buildErrorMsg(action, transactionId));
      short rc;
      if (ex instanceof P11UnknownEntityException) {
        rc = P11ProxyConstants.RC_DUPLICATE_ENTITY;
      } else if (ex instanceof P11DuplicateEntityException) {
        rc = P11ProxyConstants.RC_DUPLICATE_ENTITY;
      } else if (ex instanceof P11UnsupportedMechanismException) {
        rc = P11ProxyConstants.RC_UNSUPPORTED_MECHANISM;
      } else {
        rc = P11ProxyConstants.RC_P11_TOKENERROR;
      }

      return getResp(version, transactionId, action, rc);
    } catch (XiSecurityException | CertificateException | InvalidKeyException ex) {
      LogUtil.error(LOG, ex, buildErrorMsg(action, transactionId));
      return getResp(version, transactionId, action, P11ProxyConstants.RC_INTERNAL_ERROR);
    } catch (Throwable th) {
      LogUtil.error(LOG, th, buildErrorMsg(action, transactionId));
      return getResp(version, transactionId, action, P11ProxyConstants.RC_INTERNAL_ERROR);
    }
  } // method processPkiMessage

  private static String buildErrorMsg(short action, byte[] transactionId) {
    return "could not process action " + P11ProxyConstants.getActionName(action)
        + " (tid=" + Hex.encode(transactionId) + ")";
  }

  private P11Slot getSlot(P11CryptService p11Service, Asn1P11EntityIdentifier entityId)
      throws P11TokenException {
    return p11Service.module().getSlot(entityId.slotId().slotId());
  }

  private P11Slot getSlot(P11CryptService p11Service, P11SlotIdentifier slotId)
      throws P11TokenException {
    return p11Service.module().getSlot(slotId);
  }

  private static byte[] getResp(short version, byte[] transactionId, short rc, short action) {
    byte[] resp = new byte[14];
    IoUtil.writeShort(version, resp, 0); // version
    System.arraycopy(transactionId, 0, resp, 2, 4); // transaction Id
    IoUtil.writeInt(4, resp, 6); // length
    IoUtil.writeShort(rc, resp, 10); // RC
    IoUtil.writeShort(action, resp, 12); // action
    return resp;
  }

  private static byte[] getSuccessResp(short version, byte[] transactionId, short action,
      ASN1Object respContent) {
    byte[] encoded;
    try {
      encoded = respContent.getEncoded();
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "could not encode response ASN1Object");
      return getResp(version, transactionId, action, P11ProxyConstants.RC_INTERNAL_ERROR);
    }
    return getSuccessResp(version, transactionId, action, encoded);
  }

  private static byte[] getSuccessResp(short version, byte[] transactionId, short action,
      byte[] respContent) {
    int bodyLen = 4;
    if (respContent != null) {
      bodyLen += respContent.length;
    }
    byte[] resp = (respContent == null) ? new byte[14] : new byte[10 + bodyLen];
    IoUtil.writeShort(version, resp, 0); // version
    System.arraycopy(transactionId, 0, resp, 2, 4); // transaction Id
    IoUtil.writeInt(bodyLen, resp, 6); // length
    IoUtil.writeShort(P11ProxyConstants.RC_SUCCESS, resp, 10); // RC
    IoUtil.writeShort(action, resp, 12); // action
    if (respContent != null) {
      System.arraycopy(respContent, 0, resp, 14, respContent.length);
    }
    return resp;
  }

}
