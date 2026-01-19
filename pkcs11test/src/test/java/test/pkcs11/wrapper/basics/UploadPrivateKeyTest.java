// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;
import test.pkcs11.wrapper.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * This demo program can be used to personalize a card. It uploads a private
 * RSA key and the corresponding certificate. The key and the certificate are
 * given as a file in PKCS#12 format. The usage flags of the key object are
 * taken from the key usage flags of the certificate.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class UploadPrivateKeyTest {

  public static class Cloudhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }
  }

  public static class Luna extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.luna();
    }
  }

  public static class Ncipher extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.ncipher();
    }
  }

  public static class Sansec extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.sansec();
    }
  }

  public static class Tass extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.tass();
    }
  }

  public static class Softhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.softhsm();
    }
  }

  public static class Utimaco extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.utimaco();
    }
  }

  public static class Xihsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.xihsm();
    }
  }

  private static abstract class Base extends TestBase {

    private static final String p12ResourcePath = "/demo_cert.p12";
    private static final String p12Password = "1234";

    private static final int digitalSignature = 0;
    private static final int nonRepudiation = 1;
    private static final int keyEncipherment = 2;
    private static final int dataEncipherment = 3;
    private static final int keyAgreement = 4;
    private static final int keyCertSign = 5;
    private static final int cRLSign = 6;

    @Test
    public void main() throws Exception {
      LOG.info("##################################################");
      LOG.info("Reading private key and certificate from: {}", p12ResourcePath);
      char[] filePassword = p12Password.toCharArray();
      InputStream dataInputStream = getResourceAsStream(p12ResourcePath);
      KeyStore keystore = KeyStore.getInstance("PKCS12");
      keystore.load(dataInputStream, filePassword);

      String keyAlias = null;
      Enumeration<String> aliases = keystore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (keystore.isKeyEntry(alias)) {
          keyAlias = alias;
          break;
        }
      }

      if (keyAlias == null) {
        LOG.error("Found no private Key in the PKCS#12 file.");
        throw new IOException("Given file does not include a key!");
      }

      PrivateKey jcaPrivateKey =
          (PrivateKey) keystore.getKey(keyAlias, filePassword);

      if (!jcaPrivateKey.getAlgorithm().equals("RSA")) {
        LOG.error("Private Key in the PKCS#12 file is not a RSA key.");
        throw new IOException("Given file does not include a RSA key!");
      }

      RSAPrivateKey jcaRsaPrivateKey = (RSAPrivateKey) jcaPrivateKey;

      LOG.info("got private key");

      Certificate[] certificateChain = keystore.getCertificateChain(keyAlias);

      X509Certificate userCertificate = (X509Certificate) certificateChain[0];
      String userCommonName = Util.getCommonName(
          userCertificate.getSubjectX500Principal());

      MessageDigest sha1 = MessageDigest.getInstance("SHA1");
      byte[] encodedCert = userCertificate.getEncoded();
      byte[] certificateFingerprint = sha1.digest(encodedCert);
      boolean[] keyUsage = userCertificate.getKeyUsage();

      LOG.info("got user certificate");
      LOG.info("##################################################");
      LOG.info("creating private key object on the card... ");

      PKCS11Token token = getToken();

      // check out what attributes of the keys we may set using the mechanism
      // info
      CkMechanismInfo signatureMechanismInfo;
      if (token.supportsMechanism(CKM_RSA_PKCS, CKF_SIGN)) {
        signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_PKCS);
      } else if (token.supportsMechanism(CKM_RSA_X_509, CKF_SIGN)) {
        signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_X_509);
      } else if (token.supportsMechanism(CKM_RSA_9796, CKF_SIGN)) {
        signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_9796);
      } else if (token.supportsMechanism(CKM_RSA_PKCS_PSS, CKF_SIGN)) {
        signatureMechanismInfo = token.getMechanismInfo(CKM_RSA_PKCS_PSS);
      } else {
        signatureMechanismInfo = null;
      }

      // create private key object template
      String keyLabel = userCommonName + "'s " +
          Util.getRdnValue(userCertificate.getIssuerX500Principal(), "O");

      byte[] extnValue = userCertificate.getExtensionValue("2.5.29.14");
      byte[] newObjectID;
      if (extnValue != null) {
        newObjectID = Arrays.copyOfRange(extnValue, 4, extnValue.length);
        if (newObjectID.length != 20) {
          throw new IllegalStateException(
              "invalid extension SubjectKeyIdentifier");
        }
      } else {
        // then we simply take the fingerprint of the certificate
        newObjectID = certificateFingerprint;
      }

      Template p11RsaPrivateKey = newPrivateKey(CKK_RSA)
          .sensitive(true).token(true).private_(true).label(keyLabel)
          .id(newObjectID).subject(userCertificate.getSubjectX500Principal()
              .getEncoded());

      if (keyUsage != null) {
        // set the attributes in a way netscape does, this should work with
        // most tokens
        if (signatureMechanismInfo != null) {
          boolean decrypt =
              (keyUsage[dataEncipherment] || keyUsage[keyCertSign])
                  && signatureMechanismInfo.hasFlagBit(CKF_DECRYPT);

          boolean sign = (keyUsage[digitalSignature] || keyUsage[keyCertSign]
                  || keyUsage[cRLSign] || keyUsage[nonRepudiation])
              && signatureMechanismInfo.hasFlagBit(CKF_SIGN);

          boolean signRecover = (keyUsage[digitalSignature]
                  || keyUsage[keyCertSign] || keyUsage[cRLSign]
                  || keyUsage[nonRepudiation])
              && signatureMechanismInfo.hasFlagBit(CKF_SIGN_RECOVER);

          boolean derive = keyUsage[keyAgreement]
              && signatureMechanismInfo.hasFlagBit(CKF_DERIVE);

          boolean unwrap = keyUsage[keyEncipherment]
              && signatureMechanismInfo.hasFlagBit(CKF_UNWRAP);

          p11RsaPrivateKey.decrypt(decrypt).sign(sign)
              .signRecover(signRecover).derive(derive).unwrap(unwrap);
        } else {
          // if we have no mechanism information, we try to set the flags
          // according to the key usage only

          boolean decrypt = keyUsage[dataEncipherment] || keyUsage[keyCertSign];

          boolean sign = keyUsage[digitalSignature] || keyUsage[keyCertSign]
              || keyUsage[cRLSign] || keyUsage[nonRepudiation];

          boolean signRecover = keyUsage[digitalSignature]
              || keyUsage[keyCertSign] || keyUsage[cRLSign]
              || keyUsage[nonRepudiation];

          p11RsaPrivateKey.decrypt(decrypt).sign(sign)
              .signRecover(signRecover).derive(keyUsage[keyAgreement])
              .unwrap(keyUsage[keyEncipherment]);
        }
      } else {
        // if there is no key-usage extension in the certificate, try to set all
        // flags according to the mechanism info
        if (signatureMechanismInfo != null) {
          p11RsaPrivateKey.sign(signatureMechanismInfo.hasFlagBit(CKF_SIGN))
              .signRecover(signatureMechanismInfo.hasFlagBit(CKF_SIGN_RECOVER))
              .decrypt(signatureMechanismInfo.hasFlagBit(CKF_DECRYPT))
              .derive(signatureMechanismInfo.hasFlagBit(CKF_DERIVE))
              .unwrap(signatureMechanismInfo.hasFlagBit(CKF_UNWRAP));
        } else {
          // if we have neither mechanism info nor key usage we just try all
          p11RsaPrivateKey.sign(true).signRecover(true).decrypt(true)
              .derive(true).unwrap(true);
        }
      }

      p11RsaPrivateKey.modulus(jcaRsaPrivateKey.getModulus())
          .privateExponent(jcaRsaPrivateKey.getPrivateExponent())
          .publicExponent(((RSAPublicKey) userCertificate.getPublicKey())
              .getPublicExponent());

      if (jcaRsaPrivateKey instanceof RSAPrivateCrtKey) {
        // if we have the CRT field, we write it to the card
        // e.g. gemsafe seems to need it
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) jcaRsaPrivateKey;
        p11RsaPrivateKey.prime1(crtKey.getPrimeP())
            .prime2(crtKey.getPrimeQ())
            .exponent1(crtKey.getPrimeExponentP())
            .exponent2(crtKey.getPrimeExponentQ())
            .coefficient(crtKey.getCrtCoefficient());
      }

      LOG.info("{}", p11RsaPrivateKey);

      List<Long> newP1kcs11Objects = new ArrayList<>();
      newP1kcs11Objects.add(token.importObject(p11RsaPrivateKey));

      LOG.info("##################################################");
    }
  }

}
