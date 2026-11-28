// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x500.X500Name;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.util.ConfPairs;
import org.xipki.pkix.ca.X509PublicCaInfo;

import java.io.File;
import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * A subclass of {@link XijsonCertprofile} with an own extension: {@link ExtendedCertprofile}
 * with the profile {@code certprofile-extended.json}.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtendedCertprofileTest {

  private static final File PROFILE_FILE = new File("../assemblies/xipki-qa/src/assembly/"
      + "unfiltered/xipki-qa-cli/qa/certprofile/certprofile-extended.json");

  @Test
  public void plainXijsonProfileRejectsTheExtension() throws Exception {
    XijsonCertprofileType conf = XijsonCertprofileType.parse(PROFILE_FILE);
    CertprofileException ex = Assert.assertThrows(CertprofileException.class,
        () -> new XijsonCertprofile().initialize(conf));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("1.2.3.4.1"));
  }

  @Test
  public void extensionValueFromCaControl() throws Exception {
    ExtensionValue value = demoExtension(new ConfPairs(ExtendedCertprofile.CA_CONTROL_NAME,
        "my-value"));
    Assert.assertEquals(new Asn1Utf8String("name-a: my-value").toAsn1Primitive(), value.value());
    // as configured in the profile
    Assert.assertFalse("critical", value.isCritical());
  }

  @Test
  public void extensionValueWithoutCaControl() throws Exception {
    Assert.assertEquals(new Asn1Utf8String("name-a: UNDEF").toAsn1Primitive(),
        demoExtension(null).value());
  }

  private static ExtensionValue demoExtension(ConfPairs caControl) throws Exception {
    ExtendedCertprofile profile = new ExtendedCertprofile();
    profile.initialize(XijsonCertprofileType.parse(PROFILE_FILE));

    X500Name ca = new X500Name("CN=ca,O=myorg,C=DE");
    X509PublicCaInfo caInfo = new X509PublicCaInfo(ca, ca, BigInteger.ONE,
        null, new byte[20], null, caControl);
    X500Name subject = new X500Name("CN=a.example.org,O=myorg,C=DE");
    Instant notBefore = Instant.now();
    ExtensionValues values = profile.getExtensions(
        new ArrayList<>(profile.extensionsControl().types()), subject, subject, new HashMap<>(),
        notBefore, notBefore.plus(1, ChronoUnit.DAYS), caInfo);
    ExtensionValue value = values.getExtensionValue(ExtendedCertprofile.ID_DEMO);
    Assert.assertNotNull("extension 1.2.3.4.1", value);
    return value;
  }

}
