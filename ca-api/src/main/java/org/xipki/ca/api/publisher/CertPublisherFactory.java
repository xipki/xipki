// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.publisher;

import org.xipki.util.exception.ObjectCreationException;

import java.util.Set;

/**
 * CertPublisher factory interface.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface CertPublisherFactory {

  /**
   * Retrieves the types of supported publishers.
   * @return lower-case types of supported publishers, never {@code null}.
   */
  Set<String> getSupportedTypes();

  /**
   * Whether Publisher of given type can be created.
   * @param type
   *          Type of the publisher. Must not be {@code null}.
   * @return whether publisher of this type can be created.
   */
  boolean canCreatePublisher(String type);

  /**
   * Create new publisher of given type.
   * @param type
   *          Type of the publisher. Must not be {@code null}.
   * @return the new created publisher
   * @throws ObjectCreationException
   *           if publisher could not be created.
   */
  CertPublisher newPublisher(String type) throws ObjectCreationException;

}
