// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

import org.xipki.pkix.asn1.cmp.InfoTypeAndValue;
import org.xipki.pkix.asn1.cmp.PBMParameter;
import org.xipki.pkix.asn1.cmp.PKIFailureInfo;
import org.xipki.pkix.asn1.cmp.PKIFreeText;
import org.xipki.pkix.asn1.cmp.PKIHeader;
import org.xipki.pkix.asn1.cmp.PKIMessage;
import org.xipki.pkix.asn1.cmp.PKIStatus;
import org.xipki.pkix.asn1.crmf.EncryptedValue;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.exception.OperatorException;
import org.xipki.codec.util.StringUtil;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.CmpOIDs;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.api.ECPoint;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.crypto.core.WeierstraussCurveEnum;
import org.xipki.util.exception.NoIdleSignerException;
import org.xipki.util.exception.PkixException;
import org.xipki.util.misc.RandomUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * CMP Util.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpUtil {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private static final AlgorithmIdentifier ALG_ID =
      new AlgorithmIdentifier(XipkiOIDs.id_alg_ECIES_hkdfsha256_aes256_gcm);

  private static final Map<Integer, String> STATUS_TEXT_MAP = new HashMap<>();

  static {
    STATUS_TEXT_MAP.put(-2, "xipki_noAnswer");
    STATUS_TEXT_MAP.put(-1, "xipki_responseError");
  }

  private CmpUtil() {
  }

  public static String formatPkiStatusInfo(
      PKIStatus status, PKIFailureInfo failureInfo, String statusMessage) {
    String failInfoText = failureInfo == null ? "" : failureInfo.toString();
    String statusStr = STATUS_TEXT_MAP.get(status.value());
    if (statusStr == null) {
      statusStr = status.name();
    }

    return StringUtil.concatObjectsCap(200,
        "PKIStatusInfo {status = ", status.value(), " (", statusStr, "), ",
        "failureInfo = ", failureInfo, " (", failInfoText, "), ",
        "statusMessage = ", statusMessage, "}");
  }

  public static PKIMessage addProtection(
      PKIMessage pkiMessage, ConcurrentSigner signer,
      GeneralName signerName, boolean addSignerCert)
      throws PkixException, NoIdleSignerException {
    Args.notNull(pkiMessage, "pkiMessage");
    Args.notNull(signer, "signer");

    final GeneralName tmpSignerName;
    if (signerName != null) {
      tmpSignerName = signerName;
    } else {
      X500Name x500Name = Optional.ofNullable(signer.x509Cert()).orElseThrow(
          () -> new IllegalArgumentException("signer without certificate is not allowed"))
          .subject();
      tmpSignerName = GeneralName.ofDirectoryName(x500Name);
    }

    ProtectedPKIMessage.Builder builder = newProtectedPKIMessageBuilder(
        pkiMessage, tmpSignerName, null);

    if (addSignerCert) {
      Certificate signerCert = signer.x509Cert().getCert();
      builder.addCMPCertificate(signerCert);
    }

    Signer signer0 = signer.borrowSigner();
    ProtectedPKIMessage signedMessage;
    try {
      signedMessage = builder.build(signer0.x509Signer());
    } finally {
      signer.requiteSigner(signer0);
    }
    return signedMessage.toASN1Structure();
  }

  public static PKIMessage addProtection(
      PKIMessage pkiMessage, char[] password, PBMParameter pbmParameter,
      GeneralName signerName, byte[] senderKid) throws PkixException {
    ProtectedPKIMessage.Builder builder =
        newProtectedPKIMessageBuilder(pkiMessage, signerName, senderKid);

    return builder.build(pbmParameter, password).toASN1Structure();
  }

  private static ProtectedPKIMessage.Builder newProtectedPKIMessageBuilder(
      PKIMessage pkiMessage, GeneralName sender, byte[] senderKid) {
    PKIHeader header = pkiMessage.getHeader();
    ProtectedPKIMessage.Builder builder = new ProtectedPKIMessage.Builder(
        header.getPvno().intValueExact(), sender, header.getRecipient());
    PKIFreeText freeText = header.getFreeText();
    if (freeText != null) {
      builder.setFreeText(freeText);
    }

    InfoTypeAndValue.Seq1 generalInfo = header.getGeneralInfo();
    if (generalInfo != null) {
      for (InfoTypeAndValue gi : generalInfo) {
        builder.addGeneralInfo(gi);
      }
    }

    byte[] octet = header.recipKID();
    if (octet != null) {
      builder.setRecipKID(octet);
    }

    octet = header.recipNonce();
    if (octet != null) {
      builder.setRecipNonce(octet);
    }

    if (senderKid != null) {
      builder.setSenderKID(senderKid);
    }

    octet = header.senderNonce();
    if (octet != null) {
      builder.setSenderNonce(octet);
    }

    octet = header.transactionID();
    if (octet != null) {
      builder.setTransactionID(octet);
    }

    if (header.getMessageTime() != null) {
      builder.setMessageTime(Instant.now());
    }
    builder.setBody(pkiMessage.getBody());

    return builder;
  } // method newProtectedPKIMessageBuilder

  public static boolean isImplicitConfirm(PKIHeader header) {
    InfoTypeAndValue.Seq1 regInfos = Args.notNull(header, "header").getGeneralInfo();
    if (regInfos != null) {
      for (InfoTypeAndValue regInfo : regInfos) {
        if (CmpOIDs.it_implicitConfirm.equals(regInfo.getInfoType())) {
          return true;
        }
      }
    }

    return false;
  } // method isImplicitConfirm

  public static InfoTypeAndValue getImplicitConfirmGeneralInfo() {
    return new InfoTypeAndValue(CmpOIDs.it_implicitConfirm, Asn1Null.INSTANCE);
  }

  public static CmpUtf8Pairs extractUtf8Pairs(InfoTypeAndValue.Seq1 generalInfo)
      throws CodecException {
    if (generalInfo != null) {
      for (InfoTypeAndValue itv : generalInfo) {
        if (CmpOIDs.id_regInfo_utf8Pairs.equals(itv.getInfoType())) {
          Asn1Primitive value = itv.getInfoValue();
          if (value == null) {
            throw new CodecException("infoValue of utf8Pairs is absent");
          }

          String str = value.asUtf8String().getString();
          try {
            return new CmpUtf8Pairs(str);
          } catch (RuntimeException e) {
            throw new CodecException("invalid utf8Pairs: " + e.getMessage(), e);
          }
        }
      }
    }
    return null;
  }

  public static String[] extractCertProfile(InfoTypeAndValue.Seq1 generalInfo) {
    if (generalInfo == null) {
      return null;
    }

    for (InfoTypeAndValue itv : generalInfo) {
      if (CmpOIDs.id_it_certProfile.equals(itv.getInfoType())) {
        if (itv.getInfoValue() == null) {
          return null;
        }

        try {
          Asn1Sequence seq = itv.getInfoValue().asSequence();
          List<String> list = new ArrayList<>(seq.size());
          for (int i = 0; i < seq.size(); i++) {
            list.add(seq.getString(i).getString().toLowerCase(Locale.ROOT));
          }
          return list.isEmpty() ? null : list.toArray(new String[0]);
        } catch (CodecException e) {
          return null;
        }
      }
    }

    return null;
  }

  public static InfoTypeAndValue buildInfoTypeAndValue(CmpUtf8Pairs utf8Pairs) {
    Args.notNull(utf8Pairs, "utf8Pairs");
    return new InfoTypeAndValue(CmpOIDs.id_regInfo_utf8Pairs,
        new Asn1Utf8String(utf8Pairs.encoded()));
  }

  public static byte[] wrapCrmfContentEncryptionKey(
      byte[] keyToWrap, ECPublicKey publicKey) throws OperatorException {
    try {
      SecureRandom rnd = RandomUtil.random();
      byte[] gcmIv = new byte[12];
      rnd.nextBytes(gcmIv);
      WeierstraussCurveEnum curveEnum = curveOf(publicKey.getParams());
      byte[][] ephemeralKeyPair = curveEnum.generateKeyPair(rnd);
      byte[] ephemeralSk        = ephemeralKeyPair[0];
      byte[] ephemeralPublicKey = ephemeralKeyPair[1];

      // ECDH
      ECPoint peerECPoint = curveEnum.decodePoint(
          SubjectPublicKeyInfo.fromPublicKey(publicKey).subjectPublicKey());

      byte[] aesKey = ecdhHkdf(curveEnum, new BigInteger(1, ephemeralSk),
          peerECPoint, ephemeralPublicKey, 32);
      Cipher gcmCipher = cryptoApi.newCipher("AES/GCM/NoPadding");
      gcmCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
          new GCMParameterSpec(128, gcmIv));
      byte[] EM = gcmCipher.doFinal(keyToWrap);

      // convert the result to ASN.1 format
      return new Asn1Sequence(new Asn1OctetString(ephemeralPublicKey),
          new Asn1OctetString(gcmIv), new Asn1OctetString(EM)).getEncoded();
    } catch (Exception ex) {
      throw new OperatorException("error while generateWrappedKey", ex);
    }
  } // method wrapCrmfSymmetricKey

  public static byte[] unwrapCrmfContentEncryptionKey(
      ECPrivateKey privateKey, AlgorithmIdentifier keyAlgId, EncryptedValue ev)
      throws XiSecurityException {
    Asn1Oid keyOid = keyAlgId.getAlgorithm();
    if (!keyAlgId.getAlgorithm().equals(XipkiOIDs.id_alg_ECIES_hkdfsha256_aes256_gcm)) {
      throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
    }

    byte[] ECIESCiphertextValue = ev.encSymmKey();
    return unwrapCrmfSymmetricKey(ECIESCiphertextValue, privateKey);
  }

  private static byte[] unwrapCrmfSymmetricKey(byte[] encryptedInfo, ECPrivateKey decKey)
      throws XiSecurityException {
    try {
      Asn1Sequence seq = Asn1Sequence.fromEncoded(encryptedInfo);
      byte[] ephemeralPublicKey = seq.getOctetStringAt(0).getOctets();
      byte[] gcmIv = seq.getOctetStringAt(1).getOctets();
      byte[] EM = seq.getOctetStringAt(2).getOctets();

      WeierstraussCurveEnum curveEnum = curveOf(decKey.getParams());
      ECPoint ephemeralPoint = curveEnum.decodePoint(ephemeralPublicKey);

      byte[] aesKey = ecdhHkdf(curveEnum, decKey.getS(), ephemeralPoint, ephemeralPublicKey, 32);

      Cipher gcmCipher = cryptoApi.newCipher("AES/GCM/NoPadding");
      gcmCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
          new GCMParameterSpec(128, gcmIv));
      return gcmCipher.doFinal(EM);
    } catch (GeneralSecurityException | OperatorException | CodecException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // unwrapCrmfSymmetricKey2

  public static AlgorithmIdentifier buildCrmfAlgId() {
    return ALG_ID;
  }

  private static WeierstraussCurveEnum curveOf(ECParameterSpec ecParameterSpec)
      throws OperatorException {
    byte[] ecParams = Functions.getEcParams(ecParameterSpec.getOrder(),
              ecParameterSpec.getGenerator().getAffineX());
    WeierstraussCurveEnum curveEnum = null;
    if (ecParams != null) {
      curveEnum = WeierstraussCurveEnum.ofEcParams(ecParams);
    }

    if (curveEnum == null) {
      throw new OperatorException("invalid publicKey: unknown curve");
    }
    return curveEnum;
  }

  private static byte[] ecdhHkdf(
      WeierstraussCurveEnum curveEnum, BigInteger sk, ECPoint peerECPoint,
      byte[] ephemeralECPoint, int aesKeyByteSize) {
    byte[] encodedECDHPoint = peerECPoint.multiply(sk).normalize().getEncoded(false);
    byte[] ecdhRes = Arrays.copyOfRange(encodedECDHPoint, 1, 1 + curveEnum.getFieldByteSize());

    return KeyInfoUtil.hkdf(HashAlgo.SHA256, ephemeralECPoint, ecdhRes,
        new byte[]{'C', 'R', 'M', 'F'}, aesKeyByteSize);
  }

}
