// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.util;

/**
 * SCEP constants.
 *
 * @author Lijun Liao (xipki)
 */

public class ScepConstants {

  public static final String CT_X509_NEXT_CA_CERT =
      "application/x-x509-next-ca-cert";
  public static final String CT_X509_CA_CERT = "application/x-x509-ca-cert";
  public static final String CT_X509_CA_RA_CERT =
      "application/x-x509-ca-ra-cert";
  public static final String CT_PKI_MESSAGE = "application/x-pki-message";
  public static final String CT_TEXT_PLAIN = "text/plain";

  private ScepConstants() {
  }

}
