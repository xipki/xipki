/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.remotep11.server;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.security.exception.BadAsn1ObjectException;
import org.xipki.commons.security.exception.P11DuplicateEntityException;
import org.xipki.commons.security.exception.P11TokenException;
import org.xipki.commons.security.exception.P11UnknownEntityException;
import org.xipki.commons.security.exception.P11UnsupportedMechanismException;
import org.xipki.commons.security.exception.XiSecurityException;
import org.xipki.commons.security.pkcs11.P11CryptService;
import org.xipki.commons.security.pkcs11.P11EntityIdentifier;
import org.xipki.commons.security.pkcs11.P11Identity;
import org.xipki.commons.security.pkcs11.P11ObjectIdentifier;
import org.xipki.commons.security.pkcs11.P11Params;
import org.xipki.commons.security.pkcs11.P11Slot;
import org.xipki.commons.security.pkcs11.P11SlotIdentifier;
import org.xipki.commons.security.pkcs11.proxy.P11ProxyConstants;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1EntityIdAndCert;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1GenDSAKeypairParams;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1GenECKeypairParams;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1GenRSAKeypairParams;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1P11EntityIdentifier;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1P11ObjectIdentifier;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1P11Params;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1P11SlotIdentifier;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1RSAPkcsPssParams;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1RemoveObjectsParams;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1ServerCaps;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1SignTemplate;
import org.xipki.commons.security.util.KeyUtil;
import org.xipki.commons.security.util.X509Util;

/**
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
        actionsRequireNonNullRequest = Collections.unmodifiableSet(actions);
    }

    P11ProxyResponder() {
        Set<Short> tmpVersions = new HashSet<>();
        tmpVersions.add(P11ProxyConstants.VERSION_V1_0);
        this.versions = Collections.unmodifiableSet(tmpVersions);
    }

    public Set<Short> getVersions() {
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
    byte[] processRequest(final LocalP11CryptServicePool pool, final byte[] request) {
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
                return getResp(version, transactionId, P11ProxyConstants.RC_BAD_REQUEST,
                        action);
            }
            content = null;
        } else {
            if (actionsRequireNullRequest.contains(action)) {
                LOG.error("content is present but is not permitted");
                return getResp(version, transactionId, P11ProxyConstants.RC_BAD_REQUEST,
                        action);
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
            case P11ProxyConstants.ACTION_GET_SERVER_CAPS:
            {
                boolean readOnly = p11CryptService.getModule().isReadOnly();
                ASN1Object obj = new Asn1ServerCaps(readOnly, versions);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_ADD_CERT:
            {
                Asn1EntityIdAndCert asn1 = Asn1EntityIdAndCert.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1.getEntityId());
                X509Certificate cert = X509Util.toX509Cert(asn1.getCertificate());
                slot.addCert(asn1.getEntityId().getObjectId().getObjectId(), cert);
                return getSuccessResp(version, transactionId, action, (byte[]) null);
            }
            case P11ProxyConstants.ACTION_GEN_KEYPAIR_DSA:
            {
                Asn1GenDSAKeypairParams asn1 = Asn1GenDSAKeypairParams.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
                P11ObjectIdentifier keyId = slot.generateDSAKeypair(asn1.getP(), asn1.getQ(),
                        asn1.getG(), asn1.getLabel());
                ASN1Object obj = new Asn1P11EntityIdentifier(asn1.getSlotId().getSlotId(), keyId);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_GEN_KEYPAIR_EC:
            {
                Asn1GenECKeypairParams asn1 = Asn1GenECKeypairParams.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
                P11ObjectIdentifier keyId = slot.generateECKeypair(asn1.getCurveId().getId(),
                        asn1.getLabel());
                ASN1Object obj = new Asn1P11EntityIdentifier(asn1.getSlotId().getSlotId(), keyId);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_GEN_KEYPAIR_RSA:
            {
                Asn1GenRSAKeypairParams asn1 = Asn1GenRSAKeypairParams.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
                P11ObjectIdentifier keyId = slot.generateRSAKeypair(asn1.getKeysize(),
                        asn1.getPublicExponent(), asn1.getLabel());
                ASN1Object obj = new Asn1P11EntityIdentifier(asn1.getSlotId().getSlotId(), keyId);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_GET_CERT:
            {
                P11EntityIdentifier entityId =
                        Asn1P11EntityIdentifier.getInstance(content).getEntityId();
                X509Certificate cert = p11CryptService.getIdentity(entityId).getCertificate();
                return getSuccessResp(version, transactionId, action, cert.getEncoded());
            }
            case P11ProxyConstants.ACTION_GET_CERT_IDS:
            case P11ProxyConstants.ACTION_GET_IDENTITY_IDS:
            {
                Asn1P11SlotIdentifier slotId = Asn1P11SlotIdentifier.getInstance(content);
                P11Slot slot = p11CryptService.getModule().getSlot(slotId.getSlotId());
                Set<P11ObjectIdentifier> objectIds;
                if (P11ProxyConstants.ACTION_GET_CERT_IDS == action) {
                    objectIds = slot.getCertIdentifiers();
                } else {
                    objectIds = slot.getIdentityIdentifiers();
                }
                ASN1EncodableVector vec = new ASN1EncodableVector();
                for (P11ObjectIdentifier objectId : objectIds) {
                    vec.add(new Asn1P11ObjectIdentifier(objectId));
                }
                ASN1Object obj = new DERSequence(vec);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_GET_MECHANISMS:
            {
                P11SlotIdentifier slotId =
                        Asn1P11SlotIdentifier.getInstance(content).getSlotId();
                Set<Long> mechs = p11CryptService.getSlot(slotId).getMechanisms();
                ASN1EncodableVector vec = new ASN1EncodableVector();
                for (Long mech : mechs) {
                    vec.add(new ASN1Integer(mech));
                }
                ASN1Object obj = new DERSequence(vec);
                return getSuccessResp(version, transactionId, action, obj);
            } case P11ProxyConstants.ACTION_GET_PUBLICKEY:
            {
                P11EntityIdentifier identityId =
                        Asn1P11EntityIdentifier.getInstance(content).getEntityId();
                PublicKey pubKey = p11CryptService.getIdentity(identityId).getPublicKey();
                if (pubKey == null) {
                    throw new P11UnknownEntityException(identityId);
                }

                ASN1Object obj = KeyUtil.createSubjectPublicKeyInfo(pubKey);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_GET_SLOT_IDS:
            {
                List<P11SlotIdentifier> slotIds = p11CryptService.getModule().getSlotIdentifiers();

                ASN1EncodableVector vector = new ASN1EncodableVector();
                for (P11SlotIdentifier slotId : slotIds) {
                    vector.add(new Asn1P11SlotIdentifier(slotId));
                }
                ASN1Object obj = new DERSequence(vector);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_REMOVE_CERTS:
            {
                Asn1P11EntityIdentifier asn1 = Asn1P11EntityIdentifier.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1);
                slot.removeCerts(asn1.getObjectId().getObjectId());
                return getSuccessResp(version, transactionId, action, (byte[])null);
            }
            case P11ProxyConstants.ACTION_REMOVE_IDENTITY:
            {
                Asn1P11EntityIdentifier asn1 = Asn1P11EntityIdentifier.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1);
                slot.removeIdentity(asn1.getObjectId().getObjectId());
                return getSuccessResp(version, transactionId, action, (byte[])null);
            }
            case P11ProxyConstants.ACTION_SIGN:
            {
                Asn1SignTemplate signTemplate = Asn1SignTemplate.getInstance(content);
                long mechanism = signTemplate.getMechanism().getMechanism();
                Asn1P11Params tmpParams = signTemplate.getMechanism().getParams();
                ASN1Encodable asn1Params = null;
                if (tmpParams != null) {
                    asn1Params = tmpParams.getP11Params();
                }
                P11Params params = null;
                if (asn1Params instanceof Asn1RSAPkcsPssParams) {
                    params = Asn1RSAPkcsPssParams.getInstance(asn1Params).getPkcsPssParams();
                } else if (asn1Params != null) {
                    throw new BadAsn1ObjectException("unknown SignTemplate.params");
                }

                byte[] message = signTemplate.getMessage();
                P11Identity identity = p11CryptService.getIdentity(
                        signTemplate.getIdentityId().getEntityId());
                byte[] signature = identity.sign(mechanism, params, message);
                ASN1Object obj = new DEROctetString(signature);
                return getSuccessResp(version, transactionId, action, obj);
            }
            case P11ProxyConstants.ACTION_UPDATE_CERT:
            {
                Asn1EntityIdAndCert asn1 = Asn1EntityIdAndCert.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1.getEntityId());
                slot.updateCertificate(asn1.getEntityId().getObjectId().getObjectId(),
                        X509Util.toX509Cert(asn1.getCertificate()));
                return getSuccessResp(version, transactionId, action, (byte[])null);
            }
            case P11ProxyConstants.ACTION_REMOVE_OBJECTS:
            {
                Asn1RemoveObjectsParams asn1 = Asn1RemoveObjectsParams.getInstance(content);
                P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
                int num = slot.removeObjects(asn1.getObjectId(), asn1.getObjectLabel());
                ASN1Object obj = new ASN1Integer(num);
                return getSuccessResp(version, transactionId, action, obj);
            }
            default:
            {
                LOG.error("unsupported XiPKI action code '{}'", action);
                return getResp(version, transactionId, action,
                        P11ProxyConstants.RC_UNSUPPORTED_ACTION);
            }
            }
        } catch (BadAsn1ObjectException ex) {
            LogUtil.error(LOG, ex, "could not process decode requested content (tid="
                    + Hex.toHexString(transactionId) + ")");
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

    private static final String buildErrorMsg(short action, byte[] transactionId) {
        return "could not process action " + P11ProxyConstants.getActionName(action)
                + " (tid=" + Hex.toHexString(transactionId) + ")";
    }

    private P11Slot getSlot(final P11CryptService p11Service,
            final Asn1P11EntityIdentifier entityId) throws P11TokenException {
        return p11Service.getModule().getSlot(entityId.getSlotId().getSlotId());
    }

    private P11Slot getSlot(final P11CryptService p11Service, final Asn1P11SlotIdentifier slotId)
            throws P11TokenException {
        return p11Service.getModule().getSlot(slotId.getSlotId());
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
