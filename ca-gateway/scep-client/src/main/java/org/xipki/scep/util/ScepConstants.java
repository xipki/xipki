// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * SCEP constants.
 *
 * @author Lijun Liao
 */

public class ScepConstants {

  public static final String CT_X509_NEXT_CA_CERT = "application/x-x509-next-ca-cert";
  public static final String CT_X509_CA_CERT = "application/x-x509-ca-cert";
  public static final String CT_X509_CA_RA_CERT = "application/x-x509-ca-ra-cert";
  public static final String CT_PKI_MESSAGE = "application/x-pki-message";
  public static final String CT_TEXT_PLAIN = "text/plain";

  private static final ASN1ObjectIdentifier ID_VERISIGN = new ASN1ObjectIdentifier("2.16.840.1.113733");

  public static final ASN1ObjectIdentifier ID_PKI = ID_VERISIGN.branch("1");

  public static final ASN1ObjectIdentifier ID_ATTRIBUTES = ID_PKI.branch("9");

  public static final ASN1ObjectIdentifier ID_TRANSACTION_ID = ID_ATTRIBUTES.branch("7");

  public static final ASN1ObjectIdentifier ID_MESSAGE_TYPE = ID_ATTRIBUTES.branch("2");

  public static final ASN1ObjectIdentifier ID_PKI_STATUS = ID_ATTRIBUTES.branch("3");

  public static final ASN1ObjectIdentifier ID_FAILINFO = ID_ATTRIBUTES.branch("4");

  public static final ASN1ObjectIdentifier ID_SENDER_NONCE = ID_ATTRIBUTES.branch("5");

  public static final ASN1ObjectIdentifier ID_RECIPIENT_NONCE = ID_ATTRIBUTES.branch("6");

  public static final ASN1ObjectIdentifier ID_SMI_PKIX = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");

  public static final ASN1ObjectIdentifier ID_SCEP = ID_SMI_PKIX.branch("24");

  public static final ASN1ObjectIdentifier ID_SCEP_FAILINFOTEXT = ID_SCEP.branch("1");

  private ScepConstants() {
  }

}
