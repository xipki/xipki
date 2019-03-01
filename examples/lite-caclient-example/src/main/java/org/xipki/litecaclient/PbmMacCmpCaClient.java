/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.litecaclient;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO.
 * @author Lijun Liao
 */

public class PbmMacCmpCaClient extends CmpCaClient {

  private static final Logger LOG = LoggerFactory.getLogger(PbmMacCmpCaClient.class);

  protected byte[] kid;

  protected char[] password;

  private Set<ASN1ObjectIdentifier> trustedOwfOids = new HashSet<>();

  private Set<ASN1ObjectIdentifier> trustedMacOids = new HashSet<>();

  private int requestInterationCount = 10240;

  private AlgorithmIdentifier requestOwf;

  private AlgorithmIdentifier requestMac;

  public PbmMacCmpCaClient(String caUri, X509Certificate caCert, X500Name requestorSubject,
      X500Name responderSubject, String hashAlgo) throws Exception {
    super(caUri, caCert, requestorSubject, responderSubject, hashAlgo);
  }

  public byte[] getKid() {
    return kid;
  }

  public void setKid(byte[] kid) {
    this.kid = kid;
  }

  public char[] getPassword() {
    return password;
  }

  public void setPassword(char[] password) {
    this.password = password;
  }

  public Set<ASN1ObjectIdentifier> getTrustedOwfOids() {
    return trustedOwfOids;
  }

  public void setTrustedOwfOids(Set<ASN1ObjectIdentifier> trustedOwfOids) {
    this.trustedOwfOids = trustedOwfOids;
  }

  public Set<ASN1ObjectIdentifier> getTrustedMacOids() {
    return trustedMacOids;
  }

  public void setTrustedMacOids(Set<ASN1ObjectIdentifier> trustedMacOids) {
    this.trustedMacOids = trustedMacOids;
  }

  public int getRequestInterationCount() {
    return requestInterationCount;
  }

  public void setRequestInterationCount(int requestInterationCount) {
    this.requestInterationCount = requestInterationCount;
  }

  public AlgorithmIdentifier getRequestOwf() {
    return requestOwf;
  }

  public void setRequestOwf(AlgorithmIdentifier requestOwf) {
    this.requestOwf = requestOwf;
  }

  public AlgorithmIdentifier getRequestMac() {
    return requestMac;
  }

  public void setRequestMac(AlgorithmIdentifier requestMac) {
    this.requestMac = requestMac;
  }

  @Override
  protected boolean verifyProtection(GeneralPKIMessage pkiMessage)
      throws CMPException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    if (!protectedMsg.hasPasswordBasedMacProtection()) {
      LOG.warn("NOT_MAC_BASED: {}",
          pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
      return false;
    }

    PBMParameter parameter =
        PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters());
    ASN1ObjectIdentifier algOid = parameter.getOwf().getAlgorithm();
    if (!trustedOwfOids.contains(algOid)) {
      LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf: {})", algOid);
      return false;
    }

    algOid = parameter.getMac().getAlgorithm();
    if (!trustedMacOids.contains(algOid)) {
      LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac: {})", algOid);
      return false;
    }

    PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());
    return protectedMsg.verify(pkMacBuilder, password);
  }

  @Override
  protected byte[] decrypt(EncryptedValue ev) throws Exception {
    AlgorithmIdentifier symmAlg = ev.getSymmAlg();
    if (!PKCSObjectIdentifiers.id_PBES2.equals(symmAlg.getAlgorithm())) {
      throw new Exception("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
    }

    PBES2Parameters alg = PBES2Parameters.getInstance(symmAlg.getParameters());
    PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
    AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

    ASN1ObjectIdentifier encSchemaAlgOid = encScheme.getAlgorithm();

    int keysizeInBit;
    if (NISTObjectIdentifiers.id_aes128_GCM.equals(encSchemaAlgOid)) {
      keysizeInBit = 128;
    } else if (NISTObjectIdentifiers.id_aes192_GCM.equals(encSchemaAlgOid)) {
      keysizeInBit = 192;
    } else if (NISTObjectIdentifiers.id_aes256_GCM.equals(encSchemaAlgOid)) {
      keysizeInBit = 256;
    } else {
      throw new Exception("unsupported encryption scheme " + encSchemaAlgOid.getId());
    }

    SecretKeyFactory keyFact =
        SecretKeyFactory.getInstance(alg.getKeyDerivationFunc().getAlgorithm().getId());
    SecretKey key;

    int iterations = func.getIterationCount().intValue();
    key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), iterations,
            keysizeInBit, func.getPrf()));
    key = new SecretKeySpec(key.getEncoded(), "AES");

    String cipherAlgOid = alg.getEncryptionScheme().getAlgorithm().getId();
    Cipher cipher = Cipher.getInstance(cipherAlgOid);

    ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
    GCMParameters gcmParameters = GCMParameters.getInstance(encParams);
    GCMParameterSpec gcmParamSpec =
        new GCMParameterSpec(gcmParameters.getIcvLen() * 8, gcmParameters.getNonce());
    cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec);

    return cipher.doFinal(ev.getEncValue().getOctets());
  }

  @Override
  protected ProtectedPKIMessage build(ProtectedPKIMessageBuilder builder) throws Exception {
    builder.setSenderKID(kid);
    byte[] salt = new byte[64];
    new SecureRandom().nextBytes(salt);
    PBMParameter pbmParameter = new PBMParameter(salt, requestOwf,
        requestInterationCount, requestMac);

    try {
      PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());
      pkMacBuilder.setParameters(pbmParameter);
      return builder.build(pkMacBuilder.build(password));
    } catch (CRMFException ex) {
      throw new CMPException(ex.getMessage(), ex);
    }
  }

}
