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

package org.xipki.shell;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;

/**
 * Completers for actions.
 *
 * @author Lijun Liao
 */
public class Completers {

  @Service
  public static class ClientCrlReasonCompleter extends EnumCompleter {

    public ClientCrlReasonCompleter() {
      setTokens("unspecified", "keyCompromise", "affiliationChanged", "superseded",
          "cessationOfOperation", "certificateHold", "privilegeWithdrawn");
    }

  }

  @Service
  public static class DerPemCompleter extends EnumCompleter {

    public DerPemCompleter() {
      setTokens("pem", "der");
    }

  }

  @Service
  public static class DirCompleter extends FileCompleter {

    @Override
    protected boolean accept(Path path) {
      return path.toFile().isDirectory() && super.accept(path);
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class ECCurveNameCompleter extends EnumCompleter {

    public ECCurveNameCompleter() {
      setTokens("b-163", "b-233", "b-283", "b-409", "b-571",
          "brainpoolp160r1", "brainpoolp160t1", "brainpoolp192r1", "brainpoolp192t1",
          "brainpoolp224r1", "brainpoolp224t1", "brainpoolp256r1", "brainpoolp256t1",
          "brainpoolp320r1", "brainpoolp320t1", "brainpoolp384r1", "brainpoolp384t1",
          "brainpoolp512r1", "brainpoolp512t1",
          "c2pnb163v1", "c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2pnb208w1", "c2pnb272w1",
          "c2pnb304w1", "c2pnb368w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2tnb239v1",
          "c2tnb239v2", "c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "frp256v1",
          "k-163", "k-233", "k-283", "k-409", "k-571", "p-192", "p-224", "p-256", "p-384", "p-521",
          "prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3",
          "prime256v1",
          "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2",
          "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1",
          "secp521r1", "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1",
          "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1",
          "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "sm2p256v1",
          "wapip192v1",
          // Montgomery curves and Edwards curves
          "ed25519", "ed448", "x25519", "x448");
    }
  }

  @Service
  //CHECKSTYLE:SKIP
  public static class EdCurveNameCompleter extends EnumCompleter {

    public EdCurveNameCompleter() {
      setTokens("ed25519", "ed448", "x25519", "x448");
    }
  }

  @Service
  public static class ExtensionNameCompleter extends EnumCompleter {

    private static final Map<String, String> nameToIdMap = new HashMap<>();

    private static final Set<String> tokens;

    static {
      Map<String, String> map = new HashMap<>();
      map.put("admission", "1.3.36.8.3.3");
      map.put("auditIdentity", "1.3.6.1.5.5.7.1.4");
      map.put("authorityInfoAccess", "1.3.6.1.5.5.7.1.1");
      map.put("authorityKeyIdentifier", "2.5.29.35");
      map.put("basicConstraints", "2.5.29.19");
      map.put("biometricInfo", "1.3.6.1.5.5.7.1.2");
      map.put("cRLDistributionPoints", "2.5.29.31");
      map.put("cRLNumber", "2.5.29.20");
      map.put("certificateIssuer", "2.5.29.29");
      map.put("certificatePolicies", "2.5.29.32");
      map.put("deltaCRLIndicator", "2.5.29.27");
      map.put("extendedKeyUsage", "2.5.29.37");
      map.put("freshestCRL", "2.5.29.46");
      map.put("inhibitAnyPolicy", "2.5.29.54");
      map.put("instructionCode", "2.5.29.23");
      map.put("invalidityDate", "2.5.29.24");
      map.put("issuerAlternativeName", "2.5.29.18");
      map.put("issuingDistributionPoint", "2.5.29.28");
      map.put("keyUsage", "2.5.29.15");
      map.put("logoType", "1.3.6.1.5.5.7.1.12");
      map.put("nameConstraints", "2.5.29.30");
      map.put("noRevAvail", "2.5.29.56");
      map.put("ocspNocheck", "1.3.6.1.5.5.7.48.1.5");
      map.put("policyConstraints", "2.5.29.36");
      map.put("policyMappings", "2.5.29.33");
      map.put("privateKeyUsagePeriod", "2.5.29.16");
      map.put("qCStatements", "1.3.6.1.5.5.7.1.3");
      map.put("reasonCode", "2.5.29.21");
      map.put("subjectAlternativeName", "2.5.29.17");
      map.put("subjectDirectoryAttributes", "2.5.29.9");
      map.put("subjectInfoAccess", "1.3.6.1.5.5.7.1.11");
      map.put("subjectKeyIdentifier", "2.5.29.14");
      map.put("targetInformation", "2.5.29.55");
      map.put("tlsfeature", "1.3.6.1.5.5.7.1.24");

      tokens = new HashSet<>(map.keySet());
      for (String name : map.keySet()) {
        nameToIdMap.put(name.toLowerCase(), map.get(name));
      }
    }

    public ExtensionNameCompleter() {
      setTokens(tokens);
    }

    public static String getIdForExtensionName(String name) {
      return nameToIdMap.get(name.toLowerCase());
    }

  }

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

      for (String name : map.keySet()) {
        nameToIdMap.put(name.toLowerCase(), map.get(name));
      }
    }

    public static String getIdForUsageName(String name) {
      return nameToIdMap.get(name.toLowerCase());
    }

    public ExtKeyusageCompleter() {
      setTokens(tokens);
    }

  }

  @Service
  public static class HashAlgCompleter extends EnumCompleter {

    public HashAlgCompleter() {
      setTokens("SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SM3");
    }

  }

  @Service
  public static class KeyusageCompleter extends EnumCompleter {

    public KeyusageCompleter() {
      setTokens("digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
          "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly");
    }

  }

  @Service
  public static class SigAlgCompleter extends EnumCompleter {

    public SigAlgCompleter() {
      String[] encAlgs = {"RSA", "RSAandMGF1", "ECDSA", "DSA"};
      String[] hashAlgs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
        "SHA3-224, SHA3-256, SHA3-384, SHA3-512"};

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

      enums.add("SM3withSM2");
      setTokens(enums);
    }

  }

  @Service
  public static class SignerTypeCompleter extends EnumCompleter {

    public SignerTypeCompleter() {
      setTokens("JKS", "PKCS11", "PKCS12");
    }

  }

  @Service
  public static class YesNoCompleter extends EnumCompleter {

    public YesNoCompleter() {
      setTokens("yes", "no");
    }

  }

}
