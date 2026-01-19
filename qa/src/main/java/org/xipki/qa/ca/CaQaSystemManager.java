// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import java.io.Closeable;
import java.util.Set;

/**
 * QA system manager for CA.
 *
 * @author Lijun Liao
 *
 */

public interface CaQaSystemManager extends Closeable {

  boolean init();

  Set<String> getIssuerNames();

  /**
   * Returns the issuer information.
   * @param issuerName
   *          Name of the issuer
   * @return the issuer
   */
  IssuerInfo getIssuer(String issuerName);

  Set<String> getCertprofileNames();

  /**
   * Returns the Certprofile for the given name.
   * @param certprofileName
   *          Name of the cert profile.
   * @return the cert profile.
   */
  CertprofileQa getCertprofile(String certprofileName);

}
