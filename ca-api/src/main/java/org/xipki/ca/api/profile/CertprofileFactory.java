// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.util.exception.ObjectCreationException;

import java.util.Set;

/**
 * Certprofile factory.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CertprofileFactory {

  /**
   * Retrieves the types of supported certificate profiles.
   * @return types of supported certificate profiles, never {@code null}.
   */
  Set<String> getSupportedTypes();

  /**
   * Whether Certprofile of given type can be created.
   *
   * @param type
   *          Type of the certificate profile. Must not be {@code null}.
   * @return whether certificate profile of this type can be created.
   */
  boolean canCreateProfile(String type);

  /**
   * Create new Certprofile of given type.
   *
   * @param type
   *          Type of the certificate profile. Must not be {@code null}.
   * @return the new created certificate profile.
   * @throws ObjectCreationException
   *           if certificate profile could not be created.
   */
  Certprofile newCertprofile(String type) throws ObjectCreationException;

}
