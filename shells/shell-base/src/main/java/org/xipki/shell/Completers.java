// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;

import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;

/**
 * Completers for actions.
 *
 * @author Lijun Liao (xipki)
 */
public class Completers {

  @Service
  public static class ClientCrlReasonCompleter extends EnumCompleter {

    public ClientCrlReasonCompleter() {
      setTokens("unspecified", "keyCompromise", "affiliationChanged", "superseded",
          "cessationOfOperation", "certificateHold", "privilegeWithdrawn");
    }

  } // class ClientCrlReasonCompleter

  @Service
  public static class DerPemCompleter extends EnumCompleter {

    public DerPemCompleter() {
      setTokens("pem", "der");
    }

  } // class DerPemCompleter

  @Service
  public static class DirCompleter extends FileCompleter {

    @Override
    protected boolean accept(Path path) {
      return path.toFile().isDirectory() && super.accept(path);
    }

  } // class DirCompleter

  @Service
  public static class ECCurveNameCompleter extends EnumCompleter {

    public ECCurveNameCompleter() {
      setTokens("b-163", "b-233", "b-283", "b-409", "b-571",
          "brainpoolp160r1", "brainpoolp160t1", "brainpoolp192r1", "brainpoolp192t1", "brainpoolp224r1",
          "brainpoolp224t1", "brainpoolp256r1", "brainpoolp256t1", "brainpoolp320r1", "brainpoolp320t1",
          "brainpoolp384r1", "brainpoolp384t1", "brainpoolp512r1", "brainpoolp512t1",
          "c2pnb163v1", "c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2pnb208w1", "c2pnb272w1",
          "c2pnb304w1", "c2pnb368w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2tnb239v1",
          "c2tnb239v2", "c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "frp256v1",
          "k-163", "k-233", "k-283", "k-409", "k-571", "p-192", "p-224", "p-256", "p-384", "p-521",
          "prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3", "prime256v1",
          "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2",
          "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1",
          "secp521r1", "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1",
          "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1",
          "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "sm2p256v1", "wapip192v1",
          "ed25519", "ed448", "x25519", "x448");
    }
  } // class ECCurveNameCompleter

  @Service
  public static class EdCurveNameCompleter extends EnumCompleter {

    public EdCurveNameCompleter() {
      setTokens("ed25519", "ed448", "x25519", "x448");
    }
  } // class EdCurveNameCompleter

  @Service
  public static class ExtKeyusageCompleter extends EnumCompleter {

    private static final Map<String, String> nameToIdMap = new HashMap<>();

    private static final Set<String> tokens;

    static {
      Map<String, String> map = new HashMap<>();
      map.put("serverAuth",      "1.3.6.1.5.5.7.3.1");
      map.put("clientAuth",      "1.3.6.1.5.5.7.3.2");
      map.put("codeSigning",     "1.3.6.1.5.5.7.3.3");
      map.put("emailProtection", "1.3.6.1.5.5.7.3.4");
      map.put("ipsecEndSystem",  "1.3.6.1.5.5.7.3.5");
      map.put("ipsecTunnel",     "1.3.6.1.5.5.7.3.6");
      map.put("timeStamping",    "1.3.6.1.5.5.7.3.8");
      map.put("OCSPSigning",     "1.3.6.1.5.5.7.3.9");

      tokens = new HashSet<>(map.keySet());

      for (Entry<String, String> entry : map.entrySet()) {
        nameToIdMap.put(entry.getKey().toLowerCase(), entry.getValue());
      }
    }

    public static String getIdForUsageName(String name) {
      return nameToIdMap.get(name.toLowerCase());
    }

    public ExtKeyusageCompleter() {
      setTokens(tokens);
    }

  } // class ExtKeyusageCompleter

  @Service
  public static class HashAlgCompleter extends EnumCompleter {

    public HashAlgCompleter() {
      setTokens("SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SM3", "SHAKE128", "SHAKE256");
    }

  } // class HashAlgCompleter

  @Service
  public static class KeyusageCompleter extends EnumCompleter {

    public KeyusageCompleter() {
      setTokens("digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
          "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly");
    }

  } // class KeyusageCompleter

  @Service
  public static class SigAlgCompleter extends EnumCompleter {

    public SigAlgCompleter() {
      String[] encAlgs = {"RSA", "RSAPSS", "ECDSA", "DSA"};
      String[] hashAlgs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224, SHA3-256, SHA3-384, SHA3-512"};

      List<String> enums = new LinkedList<>();
      for (String encAlg : encAlgs) {
        for (String hashAlg : hashAlgs) {
          enums.add(hashAlg + "with" + encAlg);
        }
      }

      hashAlgs = new String[]{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"};
      for (String hashAlg : hashAlgs) {
        enums.add(hashAlg + "withPlainECDSA");
      }

      enums.addAll(Arrays.asList(
          "SM3withSM2", "SHAKE128WITHECDSA", "SHAKE256WITHECDSA", "SHAKE128WITHRSAPSS", "SHAKE256WITHRSAPSS"));
      setTokens(enums);
    }

  } // class SigAlgCompleter

  @Service
  public static class SignerTypeCompleter extends EnumCompleter {

    public SignerTypeCompleter() {
      setTokens("JCEKS", "PKCS11", "PKCS12");
    }

  } // class SignerTypeCompleter

  @Service
  public static class YesNoCompleter extends EnumCompleter {

    public YesNoCompleter() {
      setTokens("yes", "no");
    }

  } // class YesNoCompleter

}
