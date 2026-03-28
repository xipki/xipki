// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.xi;

import org.xipki.shell.completer.AbstractSetCompleter;

/**
 * Common completion providers for shell commands.
 *
 * @author Lijun Liao (xipki)
 */
public class Completers {

  public static class OutformCompleter extends AbstractSetCompleter {
    public OutformCompleter() { setTokens("der", "pem"); }
  }

  public static class HashAlgoCompleter extends AbstractSetCompleter {
    public HashAlgoCompleter() {
      setTokens("SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224",
          "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256", "SM3");
    }
  }

  public static class SigAlgoCompleter extends AbstractSetCompleter {
    public SigAlgoCompleter() {
      setTokens("SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
          "SHA3-224withRSA", "SHA3-256withRSA", "SHA3-384withRSA", "SHA3-512withRSA",
          "SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA",
          "SHA512withECDSA", "SHA1withDSA", "SHA224withDSA", "SHA256withDSA", "SHA384withDSA",
          "SHA512withDSA", "SHA1withPlain-ECDSA", "SHA224withPlain-ECDSA", "SHA256withPlain-ECDSA",
          "SHA384withPlain-ECDSA", "SHA512withPlain-ECDSA", "SM3withSM2", "ED25519", "ED448");
    }
  }

  public static class UsageCompleter extends AbstractSetCompleter {
    public UsageCompleter() { setTokens("sign", "encrypt"); }
  }

  public static class ActionCompleter extends AbstractSetCompleter {
    public ActionCompleter() { setTokens("add", "rm", "up", "info"); }
  }

  public static class CrlReasonCompleter extends AbstractSetCompleter {
    public CrlReasonCompleter() {
      setTokens("unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
            "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL",
            "privilegeWithdrawn", "aACompromise");
    }
  }

  public static class StatusCompleter extends AbstractSetCompleter {
    public StatusCompleter() { setTokens("active", "inactive"); }
  }

  public static class TripleStateCompleter extends AbstractSetCompleter {
    public TripleStateCompleter() { setTokens("yes", "no", "null"); }
  }

  public static class KeystoreTypeCompleter extends AbstractSetCompleter {
    public KeystoreTypeCompleter() { setTokens("pkcs12", "jceks"); }
  }

  public static class SignerTypeCompleter extends AbstractSetCompleter {
    public SignerTypeCompleter() { setTokens("pkcs11", "pkcs12"); }
  }

  public static class KeyUsageCompleter extends AbstractSetCompleter {
    public KeyUsageCompleter() {
      setTokens("digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly");
    }
  }

  public static class ExtKeyUsageCompleter extends AbstractSetCompleter {
    public ExtKeyUsageCompleter() {
      setTokens("serverAuth", "clientAuth", "codeSigning", "emailProtection",
          "timeStamping", "OCSPSigning");
    }
  }

  public static class YesNoCompleter extends AbstractSetCompleter {
    public YesNoCompleter() { setTokens("yes", "no"); }
  }

}
