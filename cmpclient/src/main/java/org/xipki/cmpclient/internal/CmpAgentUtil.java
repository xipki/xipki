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

package org.xipki.cmpclient.internal;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
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
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.CertprofileInfo;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.cmpclient.UnrevokeOrRemoveCertRequest;
import org.xipki.cmpclient.internal.CaConf.CmpControl;
import org.xipki.security.*;
import org.xipki.security.cmp.ProtectionResult;
import org.xipki.security.cmp.ProtectionVerificationResult;
import org.xipki.security.cmp.VerifiedPkiMessage;
import org.xipki.security.util.CmpFailureUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static org.xipki.util.Args.notNull;

/**
 * CMP agent util class.
 *
 * @author Lijun Liao
 */

class CmpAgentUtil {

  private static final Logger LOG = LoggerFactory.getLogger(CmpAgentUtil.class);

  private static final DefaultSecretKeySizeProvider KEYSIZE_PROVIDER =
      new DefaultSecretKeySizeProvider();

  /**
   * Intern status to indicate that there are errors in the response.
   */
  protected static final int PKISTATUS_RESPONSE_ERROR = -1;

  private static ASN1Encodable extractGeneralRepContent(VerifiedPkiMessage response,
      String expectedType)
          throws CmpClientException, PkiErrorException {
    notNull(response, "response");
    notNull(expectedType, "expectedType");
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new CmpClientException(CmpFailureUtil.formatPkiStatusInfo(
          content.getPKIStatusInfo()));
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
          PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
    }

    GenRepContent genRep = GenRepContent.getInstance(respBody.getContent());

    InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
    InfoTypeAndValue itv = null;
    if (itvs != null && itvs.length > 0) {
      for (InfoTypeAndValue entry : itvs) {
        if (expectedType.equals(entry.getInfoType().getId())) {
          itv = entry;
          break;
        }
      }
    }

    if (itv == null) {
      throw new CmpClientException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    return itv.getInfoValue();
  } // method extractGeneralRepContent

  static ASN1Encodable extractXipkiActionRepContent(VerifiedPkiMessage response)
      throws CmpClientException, PkiErrorException {
    ASN1Encodable itvValue = extractGeneralRepContent(notNull(response, "response"),
        ObjectIdentifiers.Xipki.id_xipki_cmp_cmpGenmsg.getId());
    return extractXiActionContent(itvValue, XiSecurityConstants.CMP_ACTION_GET_CAINFO);
  } // method extractXipkiActionRepContent

  private static ASN1Encodable extractXiActionContent(ASN1Encodable itvValue, int action)
      throws CmpClientException {
    ASN1Sequence seq;
    try {
      seq = ASN1Sequence.getInstance(notNull(itvValue, "itvValue"));
    } catch (IllegalArgumentException ex) {
      throw new CmpClientException("invalid syntax of the response");
    }

    int size = seq.size();
    if (size != 1 && size != 2) {
      throw new CmpClientException("invalid syntax of the response");
    }

    int tmpAction;
    try {
      tmpAction = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue().intValue();
    } catch (IllegalArgumentException ex) {
      throw new CmpClientException("invalid syntax of the response");
    }

    if (action != tmpAction) {
      throw new CmpClientException("received XiPKI action '" + tmpAction
          + "' instead the expected '" + action + "'");
    }

    return (size == 1) ? null : seq.getObjectAt(1);
  } // method extractXiActionContent

  static void checkProtection(VerifiedPkiMessage response)
      throws PkiErrorException {
    notNull(response, "response");

    if (!response.hasProtection()) {
      return;
    }

    ProtectionVerificationResult protectionVerificationResult =
        response.getProtectionVerificationResult();

    boolean valid;
    if (protectionVerificationResult == null) {
      valid = false;
    } else {
      ProtectionResult protectionResult = protectionVerificationResult.getProtectionResult();
      valid = protectionResult == ProtectionResult.MAC_VALID
          || protectionResult == ProtectionResult.SIGNATURE_VALID;
    }
    if (!valid) {
      throw new PkiErrorException(PKISTATUS_RESPONSE_ERROR,
          PKIFailureInfo.badMessageCheck, "message check of the response failed");
    }
  } // method checkProtection

  static byte[] decrypt(EncryptedKey ek, char[] password)
      throws XiSecurityException {
    ASN1Encodable ekValue = ek.getValue();
    if (ekValue instanceof EnvelopedData) {
      return decrypt((EnvelopedData) ekValue, password);
    } else {
      return decrypt((EncryptedValue) ekValue, password);
    }
  }

  private static byte[] decrypt(EnvelopedData ed0, char[] password)
      throws XiSecurityException {
    try {
      ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.envelopedData, ed0);
      CMSEnvelopedData ed = new CMSEnvelopedData(ci);

      RecipientInformationStore recipients = ed.getRecipientInfos();
      Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
      PasswordRecipientInformation recipient = (PasswordRecipientInformation) it.next();

      return recipient.getContent(new BcPasswordEnvelopedRecipient(password));
    } catch (CMSException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, char[] password)
      throws XiSecurityException {
    AlgorithmIdentifier symmAlg = ev.getSymmAlg();
    if (!PKCSObjectIdentifiers.id_PBES2.equals(symmAlg.getAlgorithm())) {
      throw new XiSecurityException("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
    }

    PBES2Parameters alg = PBES2Parameters.getInstance(symmAlg.getParameters());
    PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
    AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

    try {
      SecretKeyFactory keyFact =
          SecretKeyFactory.getInstance(alg.getKeyDerivationFunc().getAlgorithm().getId());
      SecretKey key;

      int iterations = func.getIterationCount().intValue();
      key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), iterations,
              KEYSIZE_PROVIDER.getKeySize(encScheme), func.getPrf()));
      key = new SecretKeySpec(key.getEncoded(), "AES");

      String cipherAlgOid = alg.getEncryptionScheme().getAlgorithm().getId();
      Cipher cipher = Cipher.getInstance(cipherAlgOid);

      ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
      GCMParameters gcmParameters = GCMParameters.getInstance(encParams);
      GCMParameterSpec gcmParamSpec =
          new GCMParameterSpec(gcmParameters.getIcvLen() * 8, gcmParameters.getNonce());
      cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec);

      return cipher.doFinal(ev.getEncValue().getOctets());
    } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
        | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException
        | InvalidAlgorithmParameterException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  static byte[] decrypt(EncryptedKey ek, PrivateKey decKey)
      throws XiSecurityException {
    ASN1Encodable ekValue = ek.getValue();
    if (ekValue instanceof EnvelopedData) {
      return decrypt((EnvelopedData) ekValue, decKey);
    } else {
      return decrypt((EncryptedValue) ekValue, decKey);
    }
  }

  private static byte[] decrypt(EnvelopedData ed0, PrivateKey decKey)
      throws XiSecurityException {
    try {
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
        recipient = new JceKeyAgreeEnvelopedRecipient(decKey).setProvider("BC");
      } else {
        recipient = new JceKeyTransEnvelopedRecipient(decKey).setProvider("BC");
      }

      return ri.getContent(recipient);
    } catch (CMSException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, PrivateKey decKey)
      throws XiSecurityException {
    AlgorithmIdentifier keyAlg = ev.getKeyAlg();
    ASN1ObjectIdentifier keyOid = keyAlg.getAlgorithm();

    byte[] symmKey;

    try {
      if (decKey instanceof RSAPrivateKey) {
        Cipher keyCipher;
        if (keyOid.equals(PKCSObjectIdentifiers.id_RSAES_OAEP)) {
          // Currently we only support the default RSAESOAEPparams
          if (keyAlg.getParameters() != null) {
            RSAESOAEPparams params = RSAESOAEPparams.getInstance(keyAlg.getParameters());
            ASN1ObjectIdentifier oid = params.getHashAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM.getAlgorithm())) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.HashAlgorithm " + oid.getId());
            }

            oid = params.getMaskGenAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION.getAlgorithm())) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.MaskGenAlgorithm " + oid.getId());
            }

            oid = params.getPSourceAlgorithm().getAlgorithm();
            if (!params.getPSourceAlgorithm().equals(RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.PSourceAlgorithm " + oid.getId());
            }
          }

          keyCipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
        } else if (keyOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
          keyCipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING");
        } else {
          throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
        }
        keyCipher.init(Cipher.DECRYPT_MODE, decKey);

        symmKey = keyCipher.doFinal(ev.getEncSymmKey().getOctets());
      } else if (decKey instanceof ECPrivateKey) {
        ASN1Sequence params = ASN1Sequence.getInstance(keyAlg.getParameters());
        final int n = params.size();
        for (int i = 0; i < n; i++) {
          if (!keyOid.equals(ObjectIdentifiers.Secg.id_ecies_specifiedParameters)) {
            throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
          }

          ASN1TaggedObject to = (ASN1TaggedObject) params.getObjectAt(i);
          int tag = to.getTagNo();
          if (tag == 0) { // KDF
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.Misc.id_iso18033_kdf2.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(HashAlgo.SHA1.getOid())) {
                throw new XiSecurityException("unsupported KeyDerivationFunction.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new XiSecurityException(
                  "unsupported KeyDerivationFunction " + algId.getAlgorithm().getId());
            }
          } else if (tag == 1) { // SymmetricEncryption
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (!ObjectIdentifiers.Secg.id_aes128_cbc_in_ecies.equals(algId.getAlgorithm())) {
              throw new XiSecurityException("unsupported SymmetricEncryption "
                  + algId.getAlgorithm().getId());
            }
          } else if (tag == 2) { // MessageAuthenticationCode
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.Secg.id_hmac_full_ecies.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(HashAlgo.SHA1.getOid())) {
                throw new XiSecurityException("unsupported MessageAuthenticationCode.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new XiSecurityException("unsupported MessageAuthenticationCode "
                  + algId.getAlgorithm().getId());
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
        keyCipher.engineInit(Cipher.DECRYPT_MODE, decKey, spec, null);

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

        byte[] bcInput = new byte[ephemeralPublicKey.length + symmetricCiphertext.length
                                  + macTag.length];
        System.arraycopy(ephemeralPublicKey, 0, bcInput, 0, ephemeralPublicKey.length);
        int offset = ephemeralPublicKey.length;
        System.arraycopy(symmetricCiphertext, 0, bcInput, offset, symmetricCiphertext.length);
        offset += symmetricCiphertext.length;
        System.arraycopy(macTag, 0, bcInput, offset, macTag.length);

        symmKey = keyCipher.engineDoFinal(bcInput, 0, bcInput.length);
      } else {
        throw new XiSecurityException("unsupported decryption key type "
            + decKey.getClass().getName());
      }

      AlgorithmIdentifier symmAlg = ev.getSymmAlg();
      ASN1ObjectIdentifier symmAlgOid = symmAlg.getAlgorithm();
      if (!symmAlgOid.equals(NISTObjectIdentifiers.id_aes128_GCM)) {
        // currently we only support AES128-GCM
        throw new XiSecurityException("unsupported symmAlg " + symmAlgOid.getId());
      }
      GCMParameters params = GCMParameters.getInstance(symmAlg.getParameters());
      Cipher dataCipher = Cipher.getInstance(symmAlgOid.getId());
      AlgorithmParameterSpec algParams =
          new GCMParameterSpec(params.getIcvLen() << 3, params.getNonce());
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), algParams);

      byte[] encValue = ev.getEncValue().getOctets();
      return dataCipher.doFinal(encValue);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  static X509CRLHolder evaluateCrlResponse(VerifiedPkiMessage response, Integer xipkiAction)
      throws CmpClientException, PkiErrorException {
    checkProtection(notNull(response, "response"));

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
    }

    ASN1ObjectIdentifier expectedType = (xipkiAction == null)
        ? CMPObjectIdentifiers.it_currentCRL : ObjectIdentifiers.Xipki.id_xipki_cmp_cmpGenmsg;

    GenRepContent genRep = GenRepContent.getInstance(respBody.getContent());

    InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
    InfoTypeAndValue itv = null;
    if (itvs != null && itvs.length > 0) {
      for (InfoTypeAndValue m : itvs) {
        if (expectedType.equals(m.getInfoType())) {
          itv = m;
          break;
        }
      }
    }

    if (itv == null) {
      throw new CmpClientException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    ASN1Encodable certListAsn1Object = (xipkiAction == null) ? itv.getInfoValue()
        : extractXiActionContent(itv.getInfoValue(), xipkiAction);

    CertificateList certList = CertificateList.getInstance(certListAsn1Object);
    return new X509CRLHolder(certList);
  } // method evaluateCrlResponse

  static RevokeCertResponse parse(VerifiedPkiMessage response,
      List<? extends UnrevokeOrRemoveCertRequest.Entry> reqEntries)
          throws CmpClientException, PkiErrorException {
    checkProtection(notNull(response, "response"));

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
          PKIBody.TYPE_REVOCATION_REP, PKIBody.TYPE_ERROR));
    }

    RevRepContent content = RevRepContent.getInstance(respBody.getContent());
    PKIStatusInfo[] statuses = content.getStatus();
    if (statuses == null || statuses.length != reqEntries.size()) {
      int statusesLen = 0;
      if (statuses != null) {
        statusesLen = statuses.length;
      }

      throw new CmpClientException(String.format(
          "incorrect number of status entries in response '%s' instead the expected '%s'",
          statusesLen, reqEntries.size()));
    }

    CertId[] revCerts = content.getRevCerts();

    RevokeCertResponse result = new RevokeCertResponse();
    for (int i = 0; i < statuses.length; i++) {
      PKIStatusInfo statusInfo = statuses[i];
      int status = statusInfo.getStatus().intValue();
      UnrevokeOrRemoveCertRequest.Entry re = reqEntries.get(i);

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null) ? null : text.getStringAt(0).getString();

        ResultEntry resultEntry = new ResultEntry.Error(re.getId(), status,
            statusInfo.getFailInfo().intValue(), statusString);
        result.addResultEntry(resultEntry);
        continue;
      }

      CertId certId = null;
      if (revCerts != null) {
        for (CertId entry : revCerts) {
          if (re.getIssuer().equals(entry.getIssuer().getName())
              && re.getSerialNumber().equals(entry.getSerialNumber().getValue())) {
            certId = entry;
            break;
          }
        }
      }

      if (certId == null) {
        LOG.warn("certId is not present in response for (issuer='{}', serialNumber={})",
            X509Util.getRfc4519Name(re.getIssuer()), LogUtil.formatCsn(re.getSerialNumber()));
        certId = new CertId(new GeneralName(re.getIssuer()), re.getSerialNumber());
      }

      result.addResultEntry(new ResultEntry.RevokeCert(re.getId(), certId));
    }

    return result;
  } // method parse

  static Extensions getCertTempExtensions(byte[] authorityKeyIdentifier)
      throws CmpClientException {
    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(authorityKeyIdentifier);
    byte[] encodedAki;
    try {
      encodedAki = aki.getEncoded();
    } catch (IOException ex) {
      throw new CmpClientException("could not encoded AuthorityKeyIdentifier", ex);
    }
    Extension extAki = new Extension(Extension.authorityKeyIdentifier, false, encodedAki);
    return new Extensions(extAki);
  } // method getCertTempExtensions

  static CaConf.CaInfo retrieveCaInfo(VerifiedPkiMessage response, String caName)
      throws CmpClientException, PkiErrorException {
    ASN1Encodable itvValue = extractXipkiActionRepContent(response);
    DERUTF8String utf8Str = DERUTF8String.getInstance(itvValue);
    String systemInfoStr = utf8Str.getString();

    LOG.debug("CAInfo for CA {}: {}", caName, systemInfoStr);
    JSONObject root;
    try {
      root = JSON.parseObject(systemInfoStr);
    } catch (RuntimeException ex) {
      throw new CmpClientException("could not parse the returned systemInfo for CA "
          + caName + ": " + ex.getMessage(), ex);
    }

    int version = root.getIntValue("version");

    if (version == 3) {
      // CACertchain
      JSONArray array = root.getJSONArray("caCertchain");
      List<X509Cert> caCertchain = new LinkedList<>();
      for (int i = 0; i < array.size(); i++) {
        String base64Cert = array.getString(i);
        X509Cert caCert;
        try {
          caCert = X509Util.parseCert(base64Cert.getBytes());
        } catch (CertificateException ex) {
          throw new CmpClientException("could no parse the CA certificate chain", ex);
        }
        caCertchain.add(caCert);
      }

      // DHPocs
      array = root.getJSONArray("dhpocs");
      List<X509Cert> dhpocs = null;
      if (array != null) {
        dhpocs = new LinkedList<>();
        for (int i = 0; i < array.size(); i++) {
          String base64Cert = array.getString(i);
          X509Cert caCert;
          try {
            caCert = X509Util.parseCert(base64Cert.getBytes());
          } catch (CertificateException ex) {
            throw new CmpClientException("could no parse the DHPoc (certificate)", ex);
          }
          dhpocs.add(caCert);
        }
      }

      // CmpControl
      CmpControl cmpControl = null;
      JSONObject jsonCmpControl = root.getJSONObject("cmpControl");
      if (jsonCmpControl != null) {
        Boolean tmpBool = jsonCmpControl.getBoolean("rrAkiRequired");
        boolean required = tmpBool != null && tmpBool;
        cmpControl = new CmpControl(required);
      }

      // certprofiles
      Set<String> profileNames = new HashSet<>();
      JSONArray jsonProfiles = root.getJSONArray("certprofiles");
      Set<CertprofileInfo> profiles = new HashSet<>();
      if (jsonProfiles != null) {
        final int size = jsonProfiles.size();
        for (int i = 0; i < size; i++) {
          JSONObject jsonProfile = jsonProfiles.getJSONObject(i);
          String name = jsonProfile.getString("name");
          String type = jsonProfile.getString("type");
          String conf = jsonProfile.getString("conf");
          CertprofileInfo profile = new CertprofileInfo(name, type, conf);
          profiles.add(profile);
          profileNames.add(name);
          LOG.debug("configured for CA {} certprofile (name={}, type={}, conf={})", caName, name,
              type, conf);
        }
      }

      LOG.info("CA {} supports profiles {}", caName, profileNames);
      return new CaConf.CaInfo(caCertchain, cmpControl, profiles, dhpocs);
    } else {
      throw new CmpClientException("unknown CAInfo version " + version);
    }
  } // method retrieveCaInfo
}
