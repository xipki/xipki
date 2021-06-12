/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.p11proxy.servlet;

import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.*;
import org.xipki.security.pkcs11.P11Params.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11Params.P11IVParams;
import org.xipki.security.pkcs11.proxy.P11ProxyConstants;
import org.xipki.security.pkcs11.proxy.asn1.*;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Hex;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The responder of P11Proxy.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ProxyResponder {
  private static final Logger LOG = LoggerFactory.getLogger(P11ProxyResponder.class);

  private static final String version;

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
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_EC_EDWARDS);
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_EC_MONTGOMERY);
    actions.add(P11ProxyConstants.ACTION_GEN_KEYPAIR_SM2);
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
    actionsRequireNonNullRequest = Collections.unmodifiableSet(actions);

    String ver;
    try {
      ver = new String(IoUtil.read(P11ProxyResponder.class.getResourceAsStream("/version"))).trim();
    } catch (Exception ex) {
      ver = "UNKNOWN";
    }
    version = ver;
  } // method static

  public P11ProxyResponder() {
    LOG.info("XiPKI PKCS#11 Proxy Responder version {}", version);
    Set<Short> tmpVersions = new HashSet<>();
    tmpVersions.add(P11ProxyConstants.VERSION_V1_0);
    this.versions = Collections.unmodifiableSet(tmpVersions);
  }

  public Set<Short> versions() {
    return versions;
  }

  /**
   * The request is constructed as follows.
   * <pre>
   * 0 - - - 1 - - - 2 - - - 3 - - - 4 - - - 5 - - - 6 - - - 7 - - - 8
   * |    Version    |        Transaction ID         |   Body ...    |
   * |   ... Length  |     Action    |   Module ID   |   Content...  |
   * |   .Content               | &lt;-- 10 + Length (offset).
   *
   * </pre>
   *
   * @param pool
   *          The pool that holds the P11CryptService.
   * @param request
   *          The request.
   * @return response.
   */
  public byte[] processRequest(LocalP11CryptServicePool pool, byte[] request) {
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
      return getResp(P11ProxyConstants.VERSION_V1_0, transactionId,
          P11ProxyConstants.RC_BAD_REQUEST, action);
    }

    // Version
    short version = IoUtil.parseShort(request, 0);
    if (!versions.contains(version)) {
      LOG.error("unsupported version {}", version);
      return getResp(P11ProxyConstants.VERSION_V1_0, transactionId,
          P11ProxyConstants.RC_UNSUPPORTED_VERSION, action);
    }

    // Length
    int reqBodyLen = IoUtil.parseInt(request, 6);
    if (reqBodyLen + 10 != reqLen) {
      LOG.error("message length unmatch");
      return getResp(version, transactionId, P11ProxyConstants.RC_BAD_REQUEST, action);
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
          AddCertParams asn1 = AddCertParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          X509Cert cert = new X509Cert(asn1.getCertificate());
          slot.addCert(cert, asn1.getControl());
          return getSuccessResp(version, transactionId, action, (byte[]) null);
        }
        case P11ProxyConstants.ACTION_DIGEST_SECRETKEY: {
          DigestSecretKeyTemplate template = DigestSecretKeyTemplate.getInstance(content);
          long mechanism = template.getMechanism().getMechanism();
          P11Identity identity = p11CryptService.getIdentity(
              template.getSlotId().getValue(), template.getObjectId().getValue());
          byte[] hashValue = identity.digestSecretKey(mechanism);
          ASN1Object obj = new DEROctetString(hashValue);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_DSA: {
          GenDSAKeypairParams asn1 = GenDSAKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId = slot.generateDSAKeypair(
              asn1.getP(), asn1.getQ(), asn1.getG(), asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_EC: {
          GenECKeypairParams asn1 = GenECKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId = slot.generateECKeypair(
              asn1.getCurveId(), asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_EC_EDWARDS: {
          GenECEdwardsOrMontgomeryKeypairParams asn1 =
              GenECEdwardsOrMontgomeryKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId = slot.generateECEdwardsKeypair(
              asn1.getCurveOid(), asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_EC_MONTGOMERY: {
          GenECEdwardsOrMontgomeryKeypairParams asn1 =
              GenECEdwardsOrMontgomeryKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId = slot.generateECMontgomeryKeypair(
              asn1.getCurveOid(), asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_RSA: {
          GenRSAKeypairParams asn1 = GenRSAKeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId = slot.generateRSAKeypair(
              asn1.getKeysize(), asn1.getPublicExponent(), asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_KEYPAIR_SM2: {
          GenSM2KeypairParams asn1 = GenSM2KeypairParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId = slot.generateSM2Keypair(asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GEN_SECRET_KEY: {
          GenSecretKeyParams asn1 = GenSecretKeyParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11IdentityId identityId =
              slot.generateSecretKey(asn1.getKeyType(), asn1.getKeysize(), asn1.getControl());
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_CERT: {
          SlotIdAndObjectId identityId = SlotIdAndObjectId.getInstance(content);
          P11SlotIdentifier slotId = identityId.getSlotId().getValue();
          P11ObjectIdentifier certId = identityId.getObjectId().getValue();
          X509Cert cert = p11CryptService.getCert(slotId, certId);
          if (cert == null) {
            throw new P11UnknownEntityException(slotId, certId);
          }

          return getSuccessResp(version, transactionId, action, cert.getEncoded());
        }
        case P11ProxyConstants.ACTION_GET_CERT_IDS:
        case P11ProxyConstants.ACTION_GET_PUBLICKEY_IDS:
        case P11ProxyConstants.ACTION_GET_IDENTITY_IDS: {
          SlotIdentifier slotId = SlotIdentifier.getInstance(content);
          P11Slot slot = p11CryptService.getModule().getSlot(slotId.getValue());
          Set<P11ObjectIdentifier> objectIds;
          if (P11ProxyConstants.ACTION_GET_CERT_IDS == action) {
            objectIds = slot.getCertIds();
          } else if (P11ProxyConstants.ACTION_GET_IDENTITY_IDS == action) {
            objectIds = slot.getIdentityKeyIds();
          } else {
            Set<P11ObjectIdentifier> identityKeyIds = slot.getIdentityKeyIds();
            objectIds = new HashSet<>();
            for (P11ObjectIdentifier identityKeyId : identityKeyIds) {
              objectIds.add(slot.getIdentity(identityKeyId).getId().getPublicKeyId());
            }
          }

          ASN1EncodableVector vec = new ASN1EncodableVector();
          for (P11ObjectIdentifier objectId : objectIds) {
            vec.add(new ObjectIdentifier(objectId));
          }
          ASN1Object obj = new DERSequence(vec);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_MECHANISMS: {
          P11SlotIdentifier slotId = SlotIdentifier.getInstance(content).getValue();
          Set<Long> mechs = p11CryptService.getSlot(slotId).getMechanisms();
          ASN1EncodableVector vec = new ASN1EncodableVector();
          for (Long mech : mechs) {
            vec.add(new ASN1Integer(mech));
          }
          ASN1Object obj = new DERSequence(vec);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_PUBLICKEY: {
          SlotIdAndObjectId identityId = SlotIdAndObjectId.getInstance(content);
          P11SlotIdentifier slotId = identityId.getSlotId().getValue();
          P11ObjectIdentifier pubKeyId = identityId.getObjectId().getValue();

          // find out the keyId
          PublicKey pubKey = null;
          P11Slot slot = getSlot(p11CryptService, slotId);
          Set<P11ObjectIdentifier> identityKeyIds = slot.getIdentityKeyIds();
          for (P11ObjectIdentifier identityKeyId : identityKeyIds) {
            P11Identity identity = slot.getIdentity(identityKeyId);
            if (pubKeyId.equals(identity.getId().getPublicKeyId())) {
              pubKey = identity.getPublicKey();
            }
          }

          if (pubKey == null) {
            throw new P11UnknownEntityException(slotId, pubKeyId);
          }

          ASN1Object obj = KeyUtil.createSubjectPublicKeyInfo(pubKey);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_SERVER_CAPS: {
          boolean readOnly = p11CryptService.getModule().isReadOnly();
          ASN1Object obj = new ServerCaps(readOnly, versions);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_GET_SLOT_IDS: {
          List<P11SlotIdentifier> slotIds = p11CryptService.getModule().getSlotIds();

          ASN1EncodableVector vector = new ASN1EncodableVector();
          for (P11SlotIdentifier slotId : slotIds) {
            vector.add(new SlotIdentifier(slotId));
          }
          ASN1Object obj = new DERSequence(vector);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_IMPORT_SECRET_KEY: {
          ImportSecretKeyParams asn1 = ImportSecretKeyParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          P11ObjectIdentifier keyId = slot.importSecretKey(asn1.getKeyType(),
              asn1.getKeyValue(), asn1.getControl());
          P11IdentityId identityId = new P11IdentityId(asn1.getSlotId(), keyId, null, null);
          ASN1Object obj = new IdentityId(identityId);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_REMOVE_CERTS: {
          SlotIdAndObjectId asn1 = SlotIdAndObjectId.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId().getValue());
          slot.removeCerts(asn1.getObjectId().getValue());
          return getSuccessResp(version, transactionId, action, (byte[])null);
        }
        case P11ProxyConstants.ACTION_REMOVE_IDENTITY: {
          SlotIdAndObjectId asn1 = SlotIdAndObjectId.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId().getValue());
          slot.removeIdentityByKeyId(asn1.getObjectId().getValue());
          return getSuccessResp(version, transactionId, action, (byte[])null);
        }
        case P11ProxyConstants.ACTION_REMOVE_OBJECTS: {
          RemoveObjectsParams asn1 = RemoveObjectsParams.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
          int num = slot.removeObjects(asn1.getOjectId(), asn1.getObjectLabel());
          ASN1Object obj = new ASN1Integer(num);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_SIGN: {
          SignTemplate signTemplate = SignTemplate.getInstance(content);
          long mechanism = signTemplate.getMechanism().getMechanism();
          org.xipki.security.pkcs11.proxy.asn1.P11Params asn1Params =
              signTemplate.getMechanism().getParams();

          P11Params params = null;

          if (asn1Params != null) {
            switch (asn1Params.getTagNo()) {
              case org.xipki.security.pkcs11.proxy.asn1.P11Params.TAG_RSA_PKCS_PSS:
                params = RSAPkcsPssParams.getInstance(asn1Params).getPkcsPssParams();
                break;
              case org.xipki.security.pkcs11.proxy.asn1.P11Params.TAG_OPAQUE:
                params = new P11ByteArrayParams(
                    ASN1OctetString.getInstance(asn1Params).getOctets());
                break;
              case org.xipki.security.pkcs11.proxy.asn1.P11Params.TAG_IV:
                params = new P11IVParams(ASN1OctetString.getInstance(asn1Params).getOctets());
                break;
              default:
                throw new BadAsn1ObjectException(
                    "unknown SignTemplate.params: unknown tag " + asn1Params.getTagNo());
            }
          }

          byte[] message = signTemplate.getMessage();
          P11Identity identity = p11CryptService.getIdentity(signTemplate.getSlotId().getValue(),
              signTemplate.getObjectId().getValue());
          if (identity == null) {
            return getResp(version, transactionId, P11ProxyConstants.RC_UNKNOWN_ENTITY, action);
          }

          byte[] signature = identity.sign(mechanism, params, message);
          ASN1Object obj = new DEROctetString(signature);
          return getSuccessResp(version, transactionId, action, obj);
        }
        case P11ProxyConstants.ACTION_UPDATE_CERT: {
          ObjectIdAndCert asn1 = ObjectIdAndCert.getInstance(content);
          P11Slot slot = getSlot(p11CryptService, asn1.getSlotId().getValue());
          slot.updateCertificate(asn1.getObjectId().getValue(),
              new X509Cert(asn1.getCertificate()));
          return getSuccessResp(version, transactionId, action, (byte[])null);
        }
        default: {
          LOG.error("unsupported XiPKI action code '{}'", action);
          return getResp(version, transactionId, P11ProxyConstants.RC_UNSUPPORTED_ACTION, action);
        }
      }
    } catch (BadAsn1ObjectException ex) {
      LogUtil.error(LOG, ex, "could not process decode requested content (tid="
          + Hex.encode(transactionId) + ")");
      return getResp(version, transactionId, P11ProxyConstants.RC_BAD_REQUEST, action);
    } catch (P11TokenException ex) {
      LogUtil.error(LOG, ex, buildErrorMsg(action, transactionId));
      short rc;
      if (ex instanceof P11UnknownEntityException) {
        rc = P11ProxyConstants.RC_UNKNOWN_ENTITY;
      } else if (ex instanceof P11DuplicateEntityException) {
        rc = P11ProxyConstants.RC_DUPLICATE_ENTITY;
      } else if (ex instanceof P11UnsupportedMechanismException) {
        rc = P11ProxyConstants.RC_UNSUPPORTED_MECHANISM;
      } else {
        rc = P11ProxyConstants.RC_P11_TOKENERROR;
      }

      return getResp(version, transactionId, rc, action);
    } catch (Throwable th) {
      LogUtil.error(LOG, th, buildErrorMsg(action, transactionId));
      return getResp(version, transactionId, P11ProxyConstants.RC_INTERNAL_ERROR, action);
    }
  } // method processRequest

  private static String buildErrorMsg(short action, byte[] transactionId) {
    return "could not process action " + P11ProxyConstants.getActionName(action)
        + " (tid=" + Hex.encode(transactionId) + ")";
  }

  private P11Slot getSlot(P11CryptService p11Service, P11SlotIdentifier slotId)
      throws P11TokenException {
    P11Slot slot = p11Service.getModule().getSlot(slotId);
    if (slot == null) {
      throw new P11UnknownEntityException(slotId);
    }
    return slot;
  } // method getSlot

  private static byte[] getResp(short version, byte[] transactionId, short rc, short action) {
    byte[] resp = new byte[14];
    IoUtil.writeShort(version, resp, 0); // version
    System.arraycopy(transactionId, 0, resp, 2, 4); // transaction Id
    IoUtil.writeInt(4, resp, 6); // length
    IoUtil.writeShort(rc, resp, 10); // RC
    IoUtil.writeShort(action, resp, 12); // action
    return resp;
  } // method getResp

  private static byte[] getSuccessResp(short version, byte[] transactionId, short action,
      ASN1Object respContent) {
    byte[] encoded;
    try {
      encoded = respContent.getEncoded();
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "could not encode response ASN1Object");
      return getResp(version, transactionId, P11ProxyConstants.RC_INTERNAL_ERROR, action);
    }
    return getSuccessResp(version, transactionId, action, encoded);
  } // method getSuccessResp

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
  } // method getSuccessResp

}
