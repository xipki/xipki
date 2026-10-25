// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.xi;

import org.xipki.pkix.util.misc.PemEncoder;
import org.xipki.pkix.util.password.PasswordResolverException;
import org.xipki.pkix.util.password.Passwords;
import org.xipki.shell.ShellBaseCommand;

import java.io.IOException;

/**
 * Base for the XiPKI commands: passwords resolved by {@link Passwords} (e.g. OBF:, PBE:) and
 * DER / PEM output of certificates and CRLs.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class XiShellBaseCommand extends ShellBaseCommand {

  protected char[] readPassword(String prompt) throws IOException, PasswordResolverException {
    char[] password = readSecret(prompt);
    if (password == null || password.length == 0) {
      return password;
    }
    return Passwords.resolvePassword(new String(password));
  }

  protected char[] readPasswordIfNotSet(String prompt, String passwordHint)
      throws IOException, PasswordResolverException {
    return passwordHint != null ? Passwords.resolvePassword(passwordHint) : readPassword(prompt);
  }

  protected byte[] encodeCert(byte[] encodedCert, String outform) throws IOException {
    return derPemEncode(encodedCert, outform, "certificate", PemEncoder.PemLabel.CERTIFICATE);
  }

  protected byte[] encodeCrl(byte[] encodedCrl, String outform) throws IOException {
    return derPemEncode(encodedCrl, outform, "CRL", PemEncoder.PemLabel.X509_CRL);
  }

  protected byte[] derPemEncode(
      byte[] encoded, String outform, String contentType, PemEncoder.PemLabel pemLabel)
      throws IOException {
    if ("pem".equalsIgnoreCase(outform)) {
      return PemEncoder.encode(encoded, pemLabel);
    } else if ("der".equalsIgnoreCase(outform)) {
      return encoded;
    } else {
      throw new IOException("unknown " + contentType + " outform " + outform);
    }
  }

  protected byte[] derPemEncode(byte[] encoded, String outform, PemEncoder.PemLabel pemLabel)
      throws IOException {
    return derPemEncode(encoded, outform, "output", pemLabel);
  }

}
