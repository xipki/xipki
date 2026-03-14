// Copyright (c) 2013-2026 xipki. All rights reserved.
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
          "superseded", "cessationOfOperation", "certificateHold", "privilegeWithdrawn");
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
      setTokens("digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
          "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly");
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
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SM3", "SHAKE128", "SHAKE256");
    }

  } // class HashAlgCompleter

  @Service
  public static class SigAlgCompleter extends EnumCompleter {

    public SigAlgCompleter() {
      setTokens(
          "RSA-SHA1",     "RSA-SHA224",    "RSA-SHA256",    "RSA-SHA384", "RSA-SHA512",
          "RSA-SHA3-224", "RSA-SHA3-256",  "RSA-SHA3-384",  "RSA-SHA3-512",
          "RSAPSS-SHA1",  "RSAPSS-SHA224", "RSAPSS-SHA256", "RSAPSS-SHA384",
          "RSAPSS-SHA512", "RSAPSS-SHA3-224", "RSAPSS-SHA3-256", "RSAPSS-SHA3-384",
          "RSAPSS-SHA3-512", "RSAPSS-SHAKE128", "RSAPSS-SHAKE256",
          "ECDSA-SHA1", "ECDSA-SHA224", "ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512",
          "ECDSA-SHA3-224", "ECDSA-SHA3-256", "ECDSA-SHA3-384", "ECDSA-SHA3-512",
          "SM2-SM3", "ECDSA-SHAKE128", "ECDSA-SHAKE256", "ED25519", "ED448",
          "MLDSA44", "MLDSA65", "MLDSA87", "KEM-HMAC-SHA256",
          "MLDSA44-RSA2048", "MLDSA44-ED25519", "MLDSA44-P256",
          "MLDSA65-RSA3072", "MLDSA65-RSA4096", "MLDSA65-P256",
          "MLDSA65-P384",    "MLDSA65-BP256",   "MLDSA65-ED25519",
          "MLDSA87-P384",    "MLDSA87-BP384",   "MLDSA87-ED448",
          "MLDSA87-RSA3072", "MLDSA87-RSA4096", "MLDSA87-P521");
    }

  }

}
