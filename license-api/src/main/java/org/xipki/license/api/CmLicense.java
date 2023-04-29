// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.license.api;

/**
 * CM License Feature.
 *
 * @author Lijun Liao (xipki)
 */
public interface CmLicense {

  /**
   * Whether the license is valid. The criteria may be the validity period,
   * license signature, or any other criteria.
   * @return true if the license is valid, false otherwise.
   */
  boolean isValid();

  boolean grantAllCAs();

  /**
   * The CA subject in BC style.
   * Output of org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE.toString(X500Name name)
   * @param caSubject the CA's subject
   * @return whether OCSP service for the given CA is allowed.
   */
  boolean grant(String caSubject);

  /**
   * Regulate the speed.
   */
  void regulateSpeed();

  /**
   * Returns maximal number of certificates.
   * @return maximal number of certificates, negative value if unlimited.
   */
  long getMaxNumberOfCerts();

}
