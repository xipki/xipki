// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Completers for actions.
 *
 * @author Lijun Liao (xipki)
 */
public class Completers {

  @Service
  public static class DirCompleter extends FileCompleter {

    @Override
    protected boolean accept(Path path) {
      return path.toFile().isDirectory() && super.accept(path);
    }

  } // class DirCompleter

  @Service
  public static class YesNoCompleter extends EnumCompleter {

    public YesNoCompleter() {
      setTokens("yes", "no");
    }

  } // class YesNoCompleter

    @Service
  public static class ClientCrlReasonCompleter extends EnumCompleter {

    public ClientCrlReasonCompleter() {
      setTokens("unspecified", "keyCompromise", "affiliationChanged",
          "superseded", "cessationOfOperation", "certificateHold",
          "privilegeWithdrawn");
    }

  } // class ClientCrlReasonCompleter

  @Service
  public static class DerPemCompleter extends EnumCompleter {

    public DerPemCompleter() {
      setTokens("pem", "der");
    }

  } // class DerPemCompleter

  @Service
  public static class KeyusageCompleter extends EnumCompleter {

    public KeyusageCompleter() {
      setTokens("digitalSignature", "contentCommitment", "keyEncipherment",
          "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
          "encipherOnly", "decipherOnly");
    }

  } // class KeyusageCompleter

  @Service
  public static class ExtKeyusageCompleter extends EnumCompleter {

    private static final Map<String, String> nameToIdMap = new HashMap<>();

    private static final Set<String> tokens;
    static {
      Map<String, String> map = new HashMap<>();
      map.put("any",                "2.5.29.37.0");
      map.put("serverAuth",         "1.3.6.1.5.5.7.3.1");
      map.put("clientAuth",         "1.3.6.1.5.5.7.3.2");
      map.put("codeSigning",        "1.3.6.1.5.5.7.3.3");
      map.put("emailProtection",    "1.3.6.1.5.5.7.3.4");
      map.put("ipsecEndSystem",     "1.3.6.1.5.5.7.3.5");
      map.put("ipsecTunnel",        "1.3.6.1.5.5.7.3.6");
      map.put("timestamping",       "1.3.6.1.5.5.7.3.8");
      map.put("OCSPSigning",        "1.3.6.1.5.5.7.3.9");
      map.put("pkinitKPClientAuth", "1.3.6.1.5.2.3.4");
      map.put("pkinitKPKDC",        "1.3.6.1.5.2.3.5");
      map.put("sshClient",          "1.3.6.1.5.5.7.3.21");
      map.put("sshServer",          "1.3.6.1.5.5.7.3.22");
      map.put("bundleSecurity",     "1.3.6.1.5.5.7.3.35");
      map.put("cmcCA",              "1.3.6.1.5.5.7.3.27");
      map.put("cmcRA",              "1.3.6.1.5.5.7.3.28");
      map.put("cmcArchive",         "1.3.6.1.5.5.7.3.29");
      map.put("cmKGA",              "1.3.6.1.5.5.7.3.32");
      map.put("certTransparency",   "1.3.6.1.4.1.11129.2.4.4");

      tokens = new HashSet<>(map.keySet());

      for (Map.Entry<String, String> entry : map.entrySet()) {
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
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SM3",
          "SHAKE128", "SHAKE256");
    }

  } // class HashAlgCompleter

  @Service
  public static class SigAlgCompleter extends EnumCompleter {

    public SigAlgCompleter() {
      setTokens(
          "SHA1WITHRSA",
          "SHA224WITHRSA",   "SHA256WITHRSA",
          "SHA384WITHRSA",   "SHA512WITHRSA",
          "SHA3-224WITHRSA", "SHA3-256WITHRSA",
          "SHA3-384WITHRSA", "SHA3-512WITHRSA",
          "SHA1WITHRSAANDMGF1",
          "SHA224WITHRSAANDMGF1",   "SHA256WITHRSAANDMGF1",
          "SHA384WITHRSAANDMGF1",   "SHA512WITHRSAANDMGF1",
          "SHA3-224WITHRSAANDMGF1", "SHA3-256WITHRSAANDMGF1",
          "SHA3-384WITHRSAANDMGF1", "SHA3-512WITHRSAANDMGF1",
          "SHAKE128WITHRSAPSS",     "SHAKE256WITHRSAPSS",
          "SHA1WITHECDSA",
          "SHA224WITHECDSA",        "SHA256WITHECDSA",
          "SHA384WITHECDSA",        "SHA512WITHECDSA",
          "SHA3-224WITHECDSA",      "SHA3-256WITHECDSA",
          "SHA3-384WITHECDSA",      "SHA3-512WITHECDSA",
          "SM3WITHSM2",
          "SHAKE128WITHECDSA",      "SHAKE256WITHECDSA",
          "ED25519", "ED448",
          "MLDSA44", "MLDSA65", "MLDSA87",
          "MLDSA44-RSA2048-PSS-SHA256",
          "MLDSA44-RSA2048-PKCS15-SHA256",
          "MLDSA44-Ed25519-SHA512",
          "MLDSA44-ECDSA-P256-SHA256",
          "MLDSA65-RSA3072-PSS-SHA512",
          "MLDSA65-RSA3072-PKCS15-SHA512",
          "MLDSA65-RSA4096-PSS-SHA512",
          "MLDSA65-RSA4096-PKCS15-SHA512",
          "MLDSA65-ECDSA-P256-SHA512",
          "MLDSA65-ECDSA-P384-SHA512",
          "MLDSA65-ECDSA-BRAINPOOLP256R1-SHA512",
          "MLDSA65-Ed25519-SHA512",
          "MLDSA87-ECDSA-P384-SHA512",
          "MLDSA87-ECDSA-BRAINPOOLP384R1-SHA512",
          "MLDSA87-Ed448-SHAKE256",
          "MLDSA87-RSA3072-PSS-SHA512",
          "MLDSA87-RSA4096-PSS-SHA512",
          "MLDSA87-ECDSA-P521-SHA512"
          );
    }

  }

}
