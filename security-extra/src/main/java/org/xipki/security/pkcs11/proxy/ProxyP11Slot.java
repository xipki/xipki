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

package org.xipki.security.pkcs11.proxy;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.proxy.asn1.AddCertParams;
import org.xipki.security.pkcs11.proxy.asn1.GenDSAKeypairParams;
import org.xipki.security.pkcs11.proxy.asn1.GenECEdwardsOrMontgomeryKeypairParams;
import org.xipki.security.pkcs11.proxy.asn1.GenECKeypairParams;
import org.xipki.security.pkcs11.proxy.asn1.GenRSAKeypairParams;
import org.xipki.security.pkcs11.proxy.asn1.GenSM2KeypairParams;
import org.xipki.security.pkcs11.proxy.asn1.GenSecretKeyParams;
import org.xipki.security.pkcs11.proxy.asn1.IdentityId;
import org.xipki.security.pkcs11.proxy.asn1.ImportSecretKeyParams;
import org.xipki.security.pkcs11.proxy.asn1.ObjectIdAndCert;
import org.xipki.security.pkcs11.proxy.asn1.ObjectIdentifier;
import org.xipki.security.pkcs11.proxy.asn1.ObjectIdentifiers;
import org.xipki.security.pkcs11.proxy.asn1.RemoveObjectsParams;
import org.xipki.security.pkcs11.proxy.asn1.SlotIdAndObjectId;
import org.xipki.security.pkcs11.proxy.asn1.SlotIdentifier;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.pkcs11.P11UnknownEntityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.StringUtil;

/**
 * {@link P11Slot} for PKCS#11 proxy.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProxyP11Slot extends P11Slot {

  private final ProxyP11Module module;

  private final P11SlotIdentifier slotId;

  private final SlotIdentifier asn1SlotId;

  ProxyP11Slot(ProxyP11Module module, P11SlotIdentifier slotId, boolean readOnly,
      P11MechanismFilter mechanismFilter)
          throws P11TokenException {
    super(module.getName(), slotId, readOnly, mechanismFilter);
    this.module = module;
    this.slotId = slotId;
    this.asn1SlotId = new SlotIdentifier(slotId);
    refresh();
  }

  @Override
  protected P11SlotRefreshResult refresh0()
      throws P11TokenException {
    P11SlotRefreshResult refreshResult = new P11SlotRefreshResult();

    // mechanisms
    List<Long> mechs = getMechanismsFromServer();
    for (Long mech : mechs) {
      refreshResult.addMechanism(mech);
    }

    // certificates
    List<P11ObjectIdentifier> certIds =
        getObjectIdsFromServer(P11ProxyConstants.ACTION_GET_CERT_IDS);
    for (P11ObjectIdentifier certId : certIds) {
      X509Cert cert = getCertificate(certId);
      if (cert != null) {
        refreshResult.addCertificate(certId, cert);
      }
    }

    // public keys
    List<P11ObjectIdentifier> pubkeyIds =
        getObjectIdsFromServer(P11ProxyConstants.ACTION_GET_PUBLICKEY_IDS);

    List<P11ObjectIdentifier> keyIds =
        getObjectIdsFromServer(P11ProxyConstants.ACTION_GET_IDENTITY_IDS);
    for (P11ObjectIdentifier keyId : keyIds) {
      byte[] id = keyId.getId();

      // find the label of public key
      P11ObjectIdentifier pubkeyid = null;
      for (P11ObjectIdentifier m : pubkeyIds) {
        if (m.matchesId(id)) {
          pubkeyid = m;
          break;
        }
      }

      java.security.PublicKey pubKey = null;
      X509Cert cert = refreshResult.getCertForId(id);
      if (cert != null) {
        pubKey = cert.getPublicKey();
      } else {
        pubKey = getPublicKey(keyId);
      }

      P11IdentityId entityId = new P11IdentityId(slotId, keyId,
          (pubkeyid == null ? null : pubkeyid.getLabel()),
          refreshResult.getCertLabelForId(id));

      ProxyP11Identity identity;
      if (pubKey == null) {
        identity = new ProxyP11Identity(this, entityId);
      } else {
        X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};
        identity = new ProxyP11Identity(this, entityId, pubKey, certs);
      }
      refreshResult.addIdentity(identity);
    }

    return refreshResult;
  } // method refresh0

  @Override
  public void close() {
  }

  private PublicKey getPublicKey(P11ObjectIdentifier objectId)
      throws P11UnknownEntityException, P11TokenException {
    ASN1Object req =
        new SlotIdAndObjectId(asn1SlotId, new ObjectIdentifier(objectId));
    byte[] resp = module.send(P11ProxyConstants.ACTION_GET_PUBLICKEY, req);
    if (resp == null) {
      return null;
    }

    SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(resp);
    try {
      return KeyUtil.generatePublicKey(pkInfo);
    } catch (InvalidKeySpecException ex) {
      throw new P11TokenException("could not generate Public Key from SubjectPublicKeyInfo:"
          + ex.getMessage(), ex);
    }
  }

  private X509Cert getCertificate(P11ObjectIdentifier objectId)
      throws P11TokenException {
    ASN1Object req =
        new SlotIdAndObjectId(asn1SlotId, new ObjectIdentifier(objectId));
    byte[] resp = module.send(P11ProxyConstants.ACTION_GET_CERT, req);
    if (resp == null) {
      return null;
    }

    try {
      return X509Util.parseCert(resp);
    } catch (CertificateException ex) {
      throw new P11TokenException("could not parse certificate:" + ex.getMessage(), ex);
    }
  }

  @Override
  public int removeObjects(byte[] id, String label)
      throws P11TokenException {
    if ((id == null || id.length == 0) && StringUtil.isBlank(label)) {
      throw new IllegalArgumentException("at least one of id and label must not be null");
    }

    RemoveObjectsParams params =
        new RemoveObjectsParams(slotId, id, label);
    byte[] resp = module.send(P11ProxyConstants.ACTION_REMOVE_OBJECTS, params);
    try {
      return ASN1Integer.getInstance(resp).getValue().intValue();
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

  @Override
  protected void removeIdentity0(P11IdentityId identityId)
      throws P11TokenException {
    ASN1Object req =  new SlotIdAndObjectId(asn1SlotId,
        new ObjectIdentifier(identityId.getKeyId()));
    module.send(P11ProxyConstants.ACTION_REMOVE_IDENTITY, req);
  }

  @Override
  protected P11ObjectIdentifier addCert0(X509Cert cert, P11NewObjectControl control)
      throws P11TokenException, CertificateException {
    AddCertParams asn1 = new AddCertParams(slotId, control, cert);
    byte[] resp = module.send(P11ProxyConstants.ACTION_ADD_CERT, asn1);
    if (resp == null) {
      return null;
    }
    ObjectIdentifier objId;
    try {
      objId = ObjectIdentifier.getInstance(resp);
    } catch (BadAsn1ObjectException ex) {
      throw new P11TokenException(
          "invalid ASN1 object Asn1P11ObjectIdentifier: " + ex.getMessage(), ex);
    }
    return objId.getValue();
  }

  @Override
  protected void removeCerts0(P11ObjectIdentifier objectId)
      throws P11TokenException {
    ASN1Object req =
        new SlotIdAndObjectId(asn1SlotId, new ObjectIdentifier(objectId));
    module.send(P11ProxyConstants.ACTION_REMOVE_CERTS, req);
  }

  @Override
  protected P11Identity generateSecretKey0(long keyType, int keysize, P11NewKeyControl control)
      throws P11TokenException {
    GenSecretKeyParams asn1 = new GenSecretKeyParams(
        slotId, control, keyType, keysize);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_SECRET_KEY, asn1);
    return parseGenerateSecretKeyResult(resp);
  }

  @Override
  protected P11Identity importSecretKey0(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {
    ImportSecretKeyParams asn1 = new ImportSecretKeyParams(
        slotId, control, keyType, keyValue);
    byte[] resp = module.send(P11ProxyConstants.ACTION_IMPORT_SECRET_KEY, asn1);
    return parseGenerateSecretKeyResult(resp);
  }

  @Override
  protected P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent,
      P11NewKeyControl control)
          throws P11TokenException {
    GenRSAKeypairParams asn1 = new GenRSAKeypairParams(
        slotId, control, keysize, publicExponent);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_KEYPAIR_RSA, asn1);
    return parseGenerateKeypairResult(resp);
  }

  @Override
  protected P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g,
      P11NewKeyControl control)
          throws P11TokenException {
    GenDSAKeypairParams asn1 =
        new GenDSAKeypairParams(slotId, control, p, q, g);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_KEYPAIR_DSA, asn1);
    return parseGenerateKeypairResult(resp);
  }

  @Override
  protected P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    GenECKeypairParams asn1 =
        new GenECKeypairParams(slotId, control, curveId);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_KEYPAIR_EC, asn1);
    return parseGenerateKeypairResult(resp);
  }

  @Override
  protected P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveOid,
      P11NewKeyControl control)
          throws P11TokenException {
    GenECEdwardsOrMontgomeryKeypairParams asn1 =
        new GenECEdwardsOrMontgomeryKeypairParams(slotId, control, curveOid);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_KEYPAIR_EC_EDWARDS, asn1);
    return parseGenerateKeypairResult(resp);
  }

  @Override
  protected P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveOid,
      P11NewKeyControl control)
          throws P11TokenException {
    GenECEdwardsOrMontgomeryKeypairParams asn1 =
        new GenECEdwardsOrMontgomeryKeypairParams(slotId, control, curveOid);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_KEYPAIR_EC, asn1);
    return parseGenerateKeypairResult(resp);
  }

  @Override
  protected P11Identity generateSM2Keypair0(P11NewKeyControl control)
      throws P11TokenException {
    GenSM2KeypairParams asn1 =
        new GenSM2KeypairParams(slotId, control);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GEN_KEYPAIR_SM2, asn1);
    return parseGenerateKeypairResult(resp);
  }

  private P11Identity parseGenerateKeypairResult(byte[] resp)
      throws P11TokenException {
    return parseGenerateKeyResult(resp, true);
  }

  private P11Identity parseGenerateSecretKeyResult(byte[] resp)
      throws P11TokenException {
    return parseGenerateKeyResult(resp, false);
  }

  private P11Identity parseGenerateKeyResult(byte[] resp, boolean needsPublicKey)
      throws P11TokenException {
    if (resp == null) {
      throw new P11TokenException("server returned no result");
    }

    IdentityId ei;
    try {
      ei = IdentityId.getInstance(resp);
    } catch (BadAsn1ObjectException ex) {
      throw new P11TokenException(
          "invalid ASN1 object Asn1P11EntityIdentifier: " + ex.getMessage(), ex);
    }

    if (!slotId.equals(ei.getValue().getSlotId())) {
      throw new P11TokenException("returned identity has different slodId");
    }

    P11IdentityId identityId = ei.getValue();
    if (needsPublicKey) {
      PublicKey publicKey = getPublicKey(identityId.getPublicKeyId());
      return new ProxyP11Identity(this, identityId, publicKey, null);
    } else {
      return new ProxyP11Identity(this, identityId);
    }
  }

  @Override
  protected void updateCertificate0(P11ObjectIdentifier objectId, X509Cert newCert)
      throws P11TokenException, CertificateException {
    ObjectIdAndCert asn1 = new ObjectIdAndCert(asn1SlotId,
        new ObjectIdentifier(objectId), newCert);
    module.send(P11ProxyConstants.ACTION_UPDATE_CERT, asn1);
  }

  private List<Long> getMechanismsFromServer()
      throws P11TokenException {
    SlotIdentifier asn1SlotId = new SlotIdentifier(slotId);
    byte[] resp = module.send(P11ProxyConstants.ACTION_GET_MECHANISMS, asn1SlotId);
    ASN1Sequence seq = requireSequence(resp);
    final int n = seq.size();

    List<Long> mechs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      long mech = ASN1Integer.getInstance(seq.getObjectAt(i)).getValue().longValue();
      mechs.add(mech);
    }
    return mechs;
  }

  private List<P11ObjectIdentifier> getObjectIdsFromServer(short action)
      throws P11TokenException {
    SlotIdentifier asn1SlotId = new SlotIdentifier(slotId);
    byte[] resp = module.send(action, asn1SlotId);

    List<ObjectIdentifier> asn1ObjectIds;
    try {
      asn1ObjectIds = ObjectIdentifiers.getInstance(resp).getObjectIds();
    } catch (BadAsn1ObjectException ex) {
      throw new P11TokenException("bad ASN1 object: " + ex.getMessage(), ex);
    }

    List<P11ObjectIdentifier> objectIds = new ArrayList<>(asn1ObjectIds.size());
    for (ObjectIdentifier asn1Id : asn1ObjectIds) {
      objectIds.add(asn1Id.getValue());
    }
    return objectIds;
  }

  private ASN1Sequence requireSequence(byte[] response)
      throws P11TokenException {
    try {
      return ASN1Sequence.getInstance(response);
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException("response is not ASN1Sequence", ex);
    }
  }

  ProxyP11Module getModule() {
    return module;
  }

  SlotIdentifier getAsn1SlotId() {
    return asn1SlotId;
  }

}
