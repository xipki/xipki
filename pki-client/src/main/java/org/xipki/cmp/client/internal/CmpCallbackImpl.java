// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipientInformation;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.xipki.cmp.client.Requestor;
import org.xipki.security.OIDs;
import org.xipki.security.bridge.CmpCallback;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.CrmfUtil;
import org.xipki.security.util.KeyUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Iterator;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpCallbackImpl implements CmpCallback {

  private static final DefaultSecretKeySizeProvider KEYSIZE_PROVIDER
      = new DefaultSecretKeySizeProvider();

  private final Requestor requestor;

  CmpCallbackImpl(Requestor requestor) {
    this.requestor = requestor;
  }

  @Override
  public byte[] decrypt(EncryptedKey encryptedKey)
      throws GeneralSecurityException {
    // decryp the encrypted private key
    byte[] decryptedValue;
    if (requestor instanceof Requestor.SignatureCmpRequestor) {
      ConcurrentSigner requestSigner = ((Requestor.SignatureCmpRequestor) requestor).signer();

      if (!(requestSigner.signingKey() instanceof PrivateKey)) {
        throw new GeneralSecurityException("no decryption key is configured");
      }

      decryptedValue = decrypt(encryptedKey, (PrivateKey) requestSigner.signingKey());
    } else {
      decryptedValue = decrypt(encryptedKey, ((Requestor.PbmMacCmpRequestor) requestor).password());
    }

    return decryptedValue;
  }

  @Override
  public byte[] decrypt(EncryptedValue encryptedKey) throws GeneralSecurityException {
    // decryp the encrypted private key
    byte[] decryptedValue;
    if (requestor instanceof Requestor.SignatureCmpRequestor) {
      ConcurrentSigner requestSigner = ((Requestor.SignatureCmpRequestor) requestor).signer();

      if (!(requestSigner.signingKey() instanceof PrivateKey)) {
        throw new GeneralSecurityException("no decryption key is configured");
      }

      decryptedValue = decrypt(encryptedKey, (PrivateKey) requestSigner.signingKey());
    } else {
      decryptedValue = decrypt(encryptedKey, ((Requestor.PbmMacCmpRequestor) requestor).password());
    }

    return decryptedValue;
  }

  private static byte[] decrypt(EncryptedKey ek, char[] password) throws GeneralSecurityException {
    ASN1Encodable ekValue = ek.getValue();
    return (ekValue instanceof EnvelopedData)
        ? decrypt((EnvelopedData) ekValue, password)
        : decrypt((EncryptedValue) ekValue, password);
  }

  private static byte[] decrypt(EnvelopedData ed0, char[] password)
      throws GeneralSecurityException {
    try {
      CMSEnvelopedData ed = new CMSEnvelopedData(new ContentInfo(OIDs.CMS.envelopedData, ed0));

      RecipientInformationStore recipients = ed.getRecipientInfos();
      Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
      PasswordRecipientInformation recipient = (PasswordRecipientInformation) it.next();

      return recipient.getContent(new JcePasswordEnvelopedRecipient(password));
    } catch (CMSException ex) {
      throw new GeneralSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, char[] password)
      throws GeneralSecurityException {
    AlgorithmIdentifier symmAlg = ev.getSymmAlg();
    if (!OIDs.Algo.id_PBES2.equals(symmAlg.getAlgorithm())) {
      throw new GeneralSecurityException("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
    }

    PBES2Parameters alg = PBES2Parameters.getInstance(symmAlg.getParameters());
    PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
    AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

    try {
      SecretKeyFactory keyFact = SecretKeyFactory.getInstance(
          alg.getKeyDerivationFunc().getAlgorithm().getId());

      SecretKey key;
      int iterations = func.getIterationCount().intValue();
      key = keyFact.generateSecret(
          new PBKDF2KeySpec(password, func.getSalt(), iterations,
              KEYSIZE_PROVIDER.getKeySize(encScheme), func.getPrf()));
      key = new SecretKeySpec(key.getEncoded(), "AES");

      String cipherAlgOid = alg.getEncryptionScheme().getAlgorithm().getId();
      Cipher cipher = Cipher.getInstance(cipherAlgOid);

      ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
      GCMParameters gcmParameters = GCMParameters.getInstance(encParams);
      GCMParameterSpec gcmParamSpec = new GCMParameterSpec(
          gcmParameters.getIcvLen() * 8, gcmParameters.getNonce());

      cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec);

      return cipher.doFinal(Asn1Util.getEncValue(ev));
    } catch (GeneralSecurityException ex) {
      throw new GeneralSecurityException(
          "Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  private static byte[] decrypt(EncryptedKey ek, PrivateKey decKey)
      throws GeneralSecurityException {
    ASN1Encodable ekValue = ek.getValue();
    return (ekValue instanceof EnvelopedData)
        ? decrypt((EnvelopedData) ekValue, decKey)
        : decrypt((EncryptedValue) ekValue, decKey);
  }

  private static byte[] decrypt(EnvelopedData ed0, PrivateKey decKey)
      throws GeneralSecurityException {
    try {
      ContentInfo ci = new ContentInfo(OIDs.CMS.envelopedData, ed0);
      CMSEnvelopedData ed = new CMSEnvelopedData(ci);

      RecipientInformationStore recipients = ed.getRecipientInfos();
      Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
      RecipientInformation ri = it.next();

      Recipient recipient;
      if (ri instanceof KeyAgreeRecipientInformation) {
        recipient = new JceKeyAgreeEnvelopedRecipient(decKey)
            .setProvider(KeyUtil.tradProviderName());
      } else if (ri instanceof KeyTransRecipientInformation) {
        recipient = new JceKeyTransEnvelopedRecipient(decKey)
            .setProvider(KeyUtil.tradProviderName());
      } else {
        throw new GeneralSecurityException(
            "unsupported RecipientInformation " + ri.getClass().getName());
      }

      return ri.getContent(recipient);
    } catch (CMSException ex) {
      throw new GeneralSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, PrivateKey decKey)
      throws GeneralSecurityException {
    AlgorithmIdentifier keyAlg = ev.getKeyAlg();
    ASN1ObjectIdentifier keyOid = keyAlg.getAlgorithm();

    byte[] symmKey;
    try {
      if (decKey instanceof RSAPrivateKey) {
        Cipher keyCipher;
        if (keyOid.equals(OIDs.Algo.id_RSAES_OAEP)) {
          // Currently we only support the default RSAESOAEPparams
          if (keyAlg.getParameters() != null) {
            RSAESOAEPparams params = RSAESOAEPparams.getInstance(keyAlg.getParameters());
            ASN1ObjectIdentifier oid = params.getHashAlgorithm().getAlgorithm();

            if (!oid.equals(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM.getAlgorithm())) {
              throw new GeneralSecurityException(
                  "unsupported RSAESOAEPparams.HashAlgorithm " + oid.getId());
            }

            oid = params.getMaskGenAlgorithm().getAlgorithm();

            if (!oid.equals(RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION.getAlgorithm())) {
              throw new GeneralSecurityException("unsupported " +
                  "RSAESOAEPparams.MaskGenAlgorithm " + oid.getId());
            }

            oid = params.getPSourceAlgorithm().getAlgorithm();
            if (!params.getPSourceAlgorithm().equals(RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)) {
              throw new GeneralSecurityException(
                  "unsupported RSAESOAEPparams.PSourceAlgorithm " + oid.getId());
            }
          }

          keyCipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
        } else if (keyOid.equals(OIDs.Algo.id_rsaEncryption)) {
          keyCipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING");
        } else {
          throw new GeneralSecurityException("unsupported keyAlg " + keyOid.getId());
        }
        keyCipher.init(Cipher.DECRYPT_MODE, decKey);

        symmKey = keyCipher.doFinal(ev.getEncSymmKey().getOctets());
      } else if (decKey instanceof ECPrivateKey) {
        try {
          if (keyOid.equals(OIDs.Xipki.id_alg_ECIES_hkdfsha256_aes256_gcm)) {
            symmKey = CrmfUtil.unwrapCrmfContentEncryptionKey((ECPrivateKey) decKey, keyAlg, ev);
          } else {
            throw new GeneralSecurityException("unsupported keyAlg " + keyOid.getId());
          }
        } catch (XiSecurityException e) {
          throw new GeneralSecurityException(e);
        }
      } else {
        throw new GeneralSecurityException("unsupported decryption key type "
            + decKey.getClass().getName());
      }

      AlgorithmIdentifier symmAlg = ev.getSymmAlg();
      ASN1ObjectIdentifier symmAlgOid = symmAlg.getAlgorithm();
      if (!symmAlgOid.equals(OIDs.Algo.id_aes128_GCM)) {
        // currently we only support AES128-GCM
        throw new GeneralSecurityException("unsupported symmAlg " + symmAlgOid.getId());
      }
      GCMParameters params = GCMParameters.getInstance(symmAlg.getParameters());
      Cipher dataCipher = Cipher.getInstance(symmAlgOid.getId());
      AlgorithmParameterSpec algParams =
          new GCMParameterSpec(params.getIcvLen() << 3, params.getNonce());
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), algParams);

      byte[] encValue = Asn1Util.getEncValue(ev);
      return dataCipher.doFinal(encValue);
    } catch (GeneralSecurityException ex) {
      throw new GeneralSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

}
