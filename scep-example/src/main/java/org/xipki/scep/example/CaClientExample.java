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

package org.xipki.scep.example;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaClientExample {

  private static final int PEM_LINE_LENGTH = 64;

  // plen: 2048, qlen: 256
  private static final BigInteger P2048_Q256_P = new BigInteger(
      "E13AC60336C29FAF1B48393D80C74B781E15E23E3F59F0827190FF016720A8E0"
      + "DAC2D4FF699EBA2196E1B9815ECAE0506441A4BC4DA97E97F2723A808EF6B634"
      + "3968906137B04B23F6540FC4B9D7C0A46635B6D52AEDD08347370B9BE43A7222"
      + "807655CB5ED480F4C66128357D0E0A2C62785DC38160645661FA569ADCE46D3B"
      + "3BFAB114613436242855F5717143D51FB365972F6B8695C2186CBAD1E8C5B4D3"
      + "1AD70876EBDD1C2191C5FB6C4804E0D38CBAA054FC7AFD25E0F2735F726D8A31"
      + "DE97431BFB6CF1AD563811830131E7D5E5117D92389406EF436A8077E69B8795"
      + "18436E33A9F221AB3A331680D0345B316F5BEBDA8FBF70612BEC734272E760BF", 16);

  private static final BigInteger P2048_Q256_Q = new BigInteger(
      "9CF2A23A8F95FEFB0CA67212991AC172FDD3F4D70401B684C3E4223D46D090E5", 16);

  private static final BigInteger P2048_Q256_G = new BigInteger(
      "1CBEF6EEB9E73C5997BF64CA8BCC33CDC6AFC5601B86FDE1B0AC4C34066DFBF9"
      + "9B80CCE264C909B32CF88CE09CB73476C0A6E701092E09C93507FE3EBD425B75"
      + "8AE3C5E3FDC1076AF237C5EF40A790CF6555EB3408BCEF212AC5A1C125A7183D"
      + "24935554C0D258BF1F6A5A6D05C0879DB92D32A0BCA3A85D42F9B436AE97E62E"
      + "0E30E53B8690D8585493D291969791EA0F3B062645440587C031CD2880481E0B"
      + "E3253A28EFFF3ACEB338A2FE4DB8F652E0FDA277268B73D5E532CF9E4E2A1CAB"
      + "738920F760012DD9389F35E0AA7C8528CE173934529397DABDFAA1E77AF83FAD"
      + "629AC102596885A06B5C670FFA838D37EB55FE7179A88F6FF927B37E0F827726", 16);

  protected static final class MyKeypair {
    private final PrivateKey privateKey;
    private final SubjectPublicKeyInfo publicKeyInfo;

    MyKeypair(PrivateKey privateKey, SubjectPublicKeyInfo publicKeyInfo) {
      this.privateKey = privateKey;
      this.publicKeyInfo = publicKeyInfo;
    }

    public PrivateKey getPrivate() {
      return privateKey;
    }

    public SubjectPublicKeyInfo getPublic() {
      return publicKeyInfo;
    }
  }

  protected static String expandPath(String path) {
    return path.startsWith("~") ? System.getProperty("user.home") + path.substring(1) : path;
  }

  protected static MyKeypair generateRsaKeypair() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(2048);

    KeyPair kp = kpGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();

    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
        new org.bouncycastle.asn1.pkcs.RSAPublicKey(pubKey.getModulus(),
            pubKey.getPublicExponent()));
    return new MyKeypair(kp.getPrivate(), subjectPublicKeyInfo);
  }

  protected static MyKeypair generateEcKeypair() throws GeneralSecurityException {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
    kpGen.initialize(spec);
    KeyPair kp = kpGen.generateKeyPair();

    ECPublicKey pub = (ECPublicKey) kp.getPublic();
    byte[] keyData = new byte[65];
    keyData[0] = 4;
    copyArray(pub.getW().getAffineX().toByteArray(), keyData, 1, 32);
    copyArray(pub.getW().getAffineY().toByteArray(), keyData, 33, 32);

    AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
        SECObjectIdentifiers.secp256r1);
    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algId, keyData);
    return new MyKeypair(kp.getPrivate(), subjectPublicKeyInfo);
  }

  protected static MyKeypair generateDsaKeypair() throws Exception {
    // plen: 2048, qlen: 256
    DSAParameterSpec spec = new DSAParameterSpec(P2048_Q256_P, P2048_Q256_Q, P2048_Q256_G);
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA");
    kpGen.initialize(spec);
    KeyPair kp = kpGen.generateKeyPair();

    DSAPublicKey dsaPubKey = (DSAPublicKey) kp.getPublic();
    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(dsaPubKey.getParams().getP()));
    vec.add(new ASN1Integer(dsaPubKey.getParams().getQ()));
    vec.add(new ASN1Integer(dsaPubKey.getParams().getG()));
    ASN1Sequence dssParams = new DERSequence(vec);

    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams),
        new ASN1Integer(dsaPubKey.getY()));

    return new MyKeypair(kp.getPrivate(), subjectPublicKeyInfo);
  }

  protected static CertificationRequest genCsr(MyKeypair keypair, String subject)
      throws GeneralSecurityException, OperatorCreationException {
    return genCsr(keypair, subject, null);
  }

  protected static CertificationRequest genCsr(MyKeypair keypair, String subject,
      String challengePassword) throws GeneralSecurityException, OperatorCreationException {
    X500Name subjectDn = new X500Name(subject);

    PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
        subjectDn, keypair.publicKeyInfo);

    if (challengePassword != null && !challengePassword.isEmpty()) {
      csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
          new DERPrintableString(challengePassword));
    }

    ContentSigner signer = buildSigner(keypair.privateKey, "SHA256");
    return csrBuilder.build(signer).toASN1Structure();
  }

  protected static void printCert(String prefix, X509Certificate cert)
            throws CertificateEncodingException {
    System.out.println(prefix);
    System.out.print("Subject: ");
    System.out.println(cert.getSubjectX500Principal());
    System.out.print(" Issuer: ");
    System.out.println(cert.getIssuerX500Principal());
    System.out.print(" Serial: 0x");
    System.out.println(cert.getSerialNumber().toString(16));
    System.out.println("NotBefore: " + cert.getNotBefore());
    System.out.println(" NotAfter: " + cert.getNotAfter());
    String pemCert = toPEM("CERTIFICATE", cert.getEncoded());
    System.out.println(pemCert);
  }

  protected static ContentSigner buildSigner(PrivateKey signingKey, String hashAlgo)
      throws OperatorCreationException {
    String keyAlgo = signingKey.getAlgorithm();
    String sigAlgo;
    if ("EC".equalsIgnoreCase(keyAlgo)) {
      sigAlgo = hashAlgo + "WITHECDSA";
    } else {
      sigAlgo = hashAlgo + "WITH" + keyAlgo;
    }
    return new JcaContentSignerBuilder(sigAlgo).build(signingKey);
  }

  private static void copyArray(byte[] source, byte[] dest, int destPos, int length) {
    int srcLen = source.length;
    if (length < srcLen) {
      boolean leadingZeros = true;
      for (int i = 0; i < srcLen - length; i++) {
        if (source[i] != 0) {
          leadingZeros = false;
          break;
        }
      }

      if (leadingZeros) {
        System.arraycopy(source, srcLen - length, dest, destPos, length);
      } else {
        throw new IllegalArgumentException("source too long");
      }
    } else {
      System.arraycopy(source, 0, dest, destPos + length - srcLen, srcLen);
    }
  }

  // CHECKSTYLE:SKIP
  private static String toPEM(String type, byte[] data) {
    byte[] base64Data = Base64.encode(data);

    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN ").append(type).append("-----\n");
    int numBlock = (base64Data.length + PEM_LINE_LENGTH - 1) / PEM_LINE_LENGTH;

    byte[] lineBytes = new byte[PEM_LINE_LENGTH];

    int offset = 0;
    for (int i = 0; i < numBlock - 1; i++) {
      System.arraycopy(base64Data, offset, lineBytes, 0, PEM_LINE_LENGTH);
      sb.append(new String(lineBytes)).append("\n");
      offset += PEM_LINE_LENGTH;
    }

    // print the last block
    lineBytes = new byte[base64Data.length - offset];
    System.arraycopy(base64Data, offset, lineBytes, 0, lineBytes.length);
    sb.append(new String(lineBytes)).append("\n");

    sb.append("-----END ").append(type).append("-----");
    return sb.toString();
  }

}
