// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12.test;

import org.xipki.security.SignAlgo;

/**
 * JUnit tests to test the signature creation and verification of PKCS#12 token
 * for the signature algorithm SHA256withRSA.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class Pkcs12SHAKE256withRSAPSSTest extends Pkcs12SignVerifyTest {

  @Override
  protected String getPkcs12File() {
    return "src/test/resources/pkcs12test/test1.p12";
  }

  @Override
  protected String getCertificateFile() {
    return "src/test/resources/pkcs12test/test1.der";
  }

  @Override
  protected SignAlgo getSignatureAlgorithm() {
    return SignAlgo.RSAPSS_SHAKE256;
  }

}
