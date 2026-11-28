// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Extension;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.util.ConfPairs;
import org.xipki.pkix.ca.X509PublicCaInfo;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Example of a certificate profile with an own extension, for the profile
 * {@code certprofile-extended.json}: the extension {@link #ID_DEMO} (1.2.3.4.1) has no
 * configuration in the profile, its value is the UTF8String {@code name-a: <value>}, where
 * {@code value} is the value of {@code name-a} in the extra control of the CA, or
 * {@code UNDEF}.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtendedCertprofile extends XijsonCertprofile {

  public static final Asn1Oid ID_DEMO = new Asn1Oid("1.2.3.4.1");

  static final String CA_CONTROL_NAME = "name-a";

  private boolean demoConfigured;

  @Override
  protected void extraReset() {
    demoConfigured = false;
  }

  @Override
  protected boolean initExtraExtension(ExtensionType extn) throws CertprofileException {
    if (ID_DEMO.equals(extn.type().oid())) {
      demoConfigured = true;
      return true;
    }
    return false;
  }

  @Override
  protected ExtensionValues getExtraExtensions(
      List<Asn1Oid> extensionsToProcess, X500Name requestedSubject, X500Name grantedSubject,
      Map<Asn1Oid, Extension> requestedExtensions, Instant notBefore, Instant notAfter,
      X509PublicCaInfo caInfo) throws CertprofileException {
    ExtensionValues values = new ExtensionValues();
    if (demoConfigured && extensionsToProcess.contains(ID_DEMO)) {
      ConfPairs caControl = caInfo.extraControl();
      String value = (caControl == null) ? null : caControl.value(CA_CONTROL_NAME);
      boolean critical = extensionsControl().getControl(ID_DEMO).isCritical();
      values.addExtension(ID_DEMO, ExtensionValue.build(critical,
          new Asn1Utf8String(CA_CONTROL_NAME + ": " + (value == null ? "UNDEF" : value))));
    }
    return values;
  }

}
