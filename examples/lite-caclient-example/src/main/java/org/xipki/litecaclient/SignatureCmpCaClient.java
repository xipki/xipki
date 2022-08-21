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

package org.xipki.litecaclient;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * CMP CA Client using signature to protect the integrity of requests.
 *
 * @author Lijun Liao
 */

public class SignatureCmpCaClient extends CmpCaClient {

  private static final Logger LOG = LoggerFactory.getLogger(SignatureCmpCaClient.class);

  private final Set<String> trustedProtectionAlgOids = new HashSet<>();

  private final ContentSigner requestorSigner;

  private final PrivateKey requestorKey;

  private final X509Certificate responderCert;

  public SignatureCmpCaClient(
      String caUri, X509Certificate caCert, PrivateKey requestorKey,
      X509Certificate requestorCert, X509Certificate responderCert, String hashAlgo)
      throws Exception {
    super(caUri, caCert,
        X500Name.getInstance(requestorCert.getSubjectX500Principal().getEncoded()),
        X500Name.getInstance(responderCert.getSubjectX500Principal().getEncoded()),
        hashAlgo);

    this.requestorKey = SdkUtil.requireNonNull("requestorKey", requestorKey);
    SdkUtil.requireNonNull("requestorCert", requestorCert);

    this.responderCert = SdkUtil.requireNonNull("responderCert", responderCert);
    this.requestorSigner = buildSigner(requestorKey);

    ASN1ObjectIdentifier[] oids = {PKCSObjectIdentifiers.sha256WithRSAEncryption,
      PKCSObjectIdentifiers.sha384WithRSAEncryption, PKCSObjectIdentifiers.sha512WithRSAEncryption,
      X9ObjectIdentifiers.ecdsa_with_SHA256, X9ObjectIdentifiers.ecdsa_with_SHA384,
      X9ObjectIdentifiers.ecdsa_with_SHA512, NISTObjectIdentifiers.dsa_with_sha256,
      NISTObjectIdentifiers.dsa_with_sha384, NISTObjectIdentifiers.dsa_with_sha512};
    for (ASN1ObjectIdentifier oid : oids) {
      trustedProtectionAlgOids.add(oid.getId());
    }
  } // constructor

  @Override
  protected boolean verifyProtection(GeneralPKIMessage pkiMessage)
      throws CMPException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    if (protectedMsg.hasPasswordBasedMacProtection()) {
      LOG.warn("protection is not signature based: {}",
          pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
      return false;
    }

    PKIHeader header = protectedMsg.getHeader();
    if (!header.getSender().equals(responderSubject)) {
      LOG.warn("not authorized responder '{}'", header.getSender());
      return false;
    }

    String algOid = protectedMsg.getHeader().getProtectionAlg().getAlgorithm().getId();
    if (!trustedProtectionAlgOids.contains(algOid)) {
      LOG.warn("PKI protection algorithm is untrusted '{}'", algOid);
      return false;
    }

    ContentVerifierProvider verifierProvider = getContentVerifierProvider(responderCert.getPublicKey());
    if (verifierProvider == null) {
      LOG.warn("not authorized responder '{}'", header.getSender());
      return false;
    }

    return protectedMsg.verify(verifierProvider);
  } // method verifyProtection

  private static ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    SdkUtil.requireNonNull("publicKey", publicKey);

    String keyAlg = publicKey.getAlgorithm().toUpperCase();

    DigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
    BcContentVerifierProviderBuilder builder;
    switch (keyAlg) {
      case "RSA":
        builder = new BcRSAContentVerifierProviderBuilder(digAlgFinder);
        break;
      case "DSA":
        builder = new BcDSAContentVerifierProviderBuilder(digAlgFinder);
        break;
      case "EC":
      case "ECDSA":
        builder = new BcECContentVerifierProviderBuilder(digAlgFinder);
        break;
      default:
        throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
    }

    AsymmetricKeyParameter keyParam;
    if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
      keyParam = new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    } else if (publicKey instanceof ECPublicKey) {
      keyParam = ECUtil.generatePublicKeyParameter(publicKey);
    } else if (publicKey instanceof DSAPublicKey) {
      keyParam = DSAUtil.generatePublicKeyParameter(publicKey);
    } else {
      throw new InvalidKeyException("unknown key " + publicKey.getClass().getName());
    }

    try {
      return builder.build(keyParam);
    } catch (OperatorCreationException ex) {
      throw new InvalidKeyException("could not build ContentVerifierProvider: " + ex.getMessage(), ex);
    }
  } // method getContentVerifierProvider

  @Override
  protected byte[] decrypt(EncryptedKey ek)
      throws Exception {
    ASN1Encodable ekValue = ek.getValue();
    if (ekValue instanceof EnvelopedData) {
      return decrypt((EnvelopedData) ekValue);
    } else {
      return decrypt((EncryptedValue) ekValue);
    }
  }

  private byte[] decrypt(EnvelopedData ed0)
      throws Exception {
    ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.envelopedData, ed0);
    CMSEnvelopedData ed = new CMSEnvelopedData(ci);

    RecipientInformationStore recipients = ed.getRecipientInfos();
    Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
    RecipientInformation ri = it.next();

    ASN1ObjectIdentifier encAlg = ri.getKeyEncryptionAlgorithm().getAlgorithm();
    Recipient recipient;
    if (encAlg.equals(CMSAlgorithm.ECDH_SHA1KDF)
        || encAlg.equals(CMSAlgorithm.ECDH_SHA224KDF)
        || encAlg.equals(CMSAlgorithm.ECDH_SHA256KDF)
        || encAlg.equals(CMSAlgorithm.ECDH_SHA384KDF)
        || encAlg.equals(CMSAlgorithm.ECDH_SHA384KDF)
        || encAlg.equals(CMSAlgorithm.ECDH_SHA512KDF)) {
      recipient = new JceKeyAgreeEnvelopedRecipient(requestorKey).setProvider("BC");
    } else {
      recipient = new JceKeyTransEnvelopedRecipient(requestorKey).setProvider("BC");
    }

    return ri.getContent(recipient);
  }

  private byte[] decrypt(EncryptedValue ev)
      throws Exception {
    AlgorithmIdentifier keyAlg = ev.getKeyAlg();
    ASN1ObjectIdentifier keyOid = keyAlg.getAlgorithm();

    byte[] symmKey;

    try {
      if (requestorKey instanceof RSAPrivateKey) {
        Cipher keyCipher;
        if (keyOid.equals(PKCSObjectIdentifiers.id_RSAES_OAEP)) {
          // Currently we only support the default RSAESOAEPparams
          if (keyAlg.getParameters() != null) {
            RSAESOAEPparams params = RSAESOAEPparams.getInstance(keyAlg.getParameters());
            ASN1ObjectIdentifier oid = params.getHashAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM.getAlgorithm())) {
              throw new Exception("unsupported RSAESOAEPparams.HashAlgorithm " + oid.getId());
            }

            oid = params.getMaskGenAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION.getAlgorithm())) {
              throw new Exception("unsupported RSAESOAEPparams.MaskGenAlgorithm " + oid.getId());
            }

            oid = params.getPSourceAlgorithm().getAlgorithm();
            if (!params.getPSourceAlgorithm().equals(RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)) {
              throw new Exception("unsupported RSAESOAEPparams.PSourceAlgorithm " + oid.getId());
            }
          }

          keyCipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
        } else if (keyOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
          keyCipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING");
        } else {
          throw new Exception("unsupported keyAlg " + keyOid.getId());
        }
        keyCipher.init(Cipher.DECRYPT_MODE, requestorKey);

        symmKey = keyCipher.doFinal(ev.getEncSymmKey().getOctets());
      } else if (requestorKey instanceof ECPrivateKey) {
        ASN1Sequence params = ASN1Sequence.getInstance(keyAlg.getParameters());
        final int n = params.size();
        for (int i = 0; i < n; i++) {
          if (!keyOid.equals(ObjectIdentifiers.id_ecies_specifiedParameters)) {
            throw new Exception("unsupported keyAlg " + keyOid.getId());
          }

          ASN1TaggedObject to = (ASN1TaggedObject) params.getObjectAt(i);
          int tag = to.getTagNo();
          if (tag == 0) { // KDF
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.id_iso18033_kdf2.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm = AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(ObjectIdentifiers.id_sha1)) {
                throw new Exception("unsupported KeyDerivationFunction.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new Exception("unsupported KeyDerivationFunction " + algId.getAlgorithm().getId());
            }
          } else if (tag == 1) { // SymmetricEncryption
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (!ObjectIdentifiers.id_aes128_cbc_in_ecies.equals(algId.getAlgorithm())) {
              throw new Exception("unsupported SymmetricEncryption " + algId.getAlgorithm().getId());
            }
          } else if (tag == 2) { // MessageAuthenticationCode
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.id_hmac_full_ecies.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(ObjectIdentifiers.id_sha1)) {
                throw new Exception("unsupported MessageAuthenticationCode.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new Exception("unsupported MessageAuthenticationCode " + algId.getAlgorithm().getId());
            }
          }
        }

        int aesKeySize = 128;
        byte[] iv = new byte[16];
        AlgorithmParameterSpec spec = new IESParameterSpec(null, null, aesKeySize, aesKeySize, iv);

        BlockCipher cbcCipher = new CBCBlockCipher(new AESEngine());
        IESCipher keyCipher = new IESCipher(
            new IESEngine(new ECDHBasicAgreement(),
                new KDF2BytesGenerator(DigestFactory.createSHA1()),
                new HMac(DigestFactory.createSHA1()),
                new PaddedBufferedBlockCipher(cbcCipher)), 16);
        // no random is required
        keyCipher.engineInit(Cipher.DECRYPT_MODE, requestorKey, spec, null);

        byte[] encSymmKey = ev.getEncSymmKey().getOctets();
        /*
         * BouncyCastle expects the input ephemeralPublicKey | symmetricCiphertext | macTag.
         * So we have to convert it from the following ASN.1 structure
        * <pre>
        * ECIES-Ciphertext-Value ::= SEQUENCE {
        *     ephemeralPublicKey ECPoint,
        *     symmetricCiphertext OCTET STRING,
        *     macTag OCTET STRING
        * }
        *
        * ECPoint ::= OCTET STRING
        * </pre>
        */
        ASN1Sequence seq = DERSequence.getInstance(encSymmKey);
        byte[] ephemeralPublicKey = DEROctetString.getInstance(seq.getObjectAt(0)).getOctets();
        byte[] symmetricCiphertext = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
        byte[] macTag = DEROctetString.getInstance(seq.getObjectAt(2)).getOctets();

        byte[] bcInput = new byte[ephemeralPublicKey.length + symmetricCiphertext.length + macTag.length];
        System.arraycopy(ephemeralPublicKey, 0, bcInput, 0, ephemeralPublicKey.length);
        int offset = ephemeralPublicKey.length;
        System.arraycopy(symmetricCiphertext, 0, bcInput, offset, symmetricCiphertext.length);
        offset += symmetricCiphertext.length;
        System.arraycopy(macTag, 0, bcInput, offset, macTag.length);

        symmKey = keyCipher.engineDoFinal(bcInput, 0, bcInput.length);
      } else {
        throw new Exception("unsupported decryption key type " + requestorKey.getClass().getName());
      }

      AlgorithmIdentifier symmAlg = ev.getSymmAlg();
      if (!symmAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_aes128_GCM)) {
        // currently we only support AES128-GCM
        throw new Exception("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
      }

      Cipher dataCipher = Cipher.getInstance(NISTObjectIdentifiers.id_aes128_GCM.getId());
      GCMParameters gcmParams = GCMParameters.getInstance(symmAlg.getParameters());
      GCMParameterSpec spec = new GCMParameterSpec(gcmParams.getIcvLen() * 8, gcmParams.getNonce());
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), spec);

      byte[] encValue = ev.getEncValue().getOctets();
      return dataCipher.doFinal(encValue);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
      throw new Exception("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  @Override
  protected ProtectedPKIMessage build(ProtectedPKIMessageBuilder builder)
      throws Exception {
    return builder.build(requestorSigner);
  }

}
