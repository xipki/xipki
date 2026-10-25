// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.publisher;

import org.xipki.codec.asn1.GenerationException;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherFactory;

import java.util.Collections;
import java.util.Set;

/**
 * OCSP Cert Publisher Factory.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspCertPublisherFactory implements CertPublisherFactory {

  private static final String TYPE = "ocsp";

  private static final Set<String> types = Set.copyOf(Collections.singletonList(TYPE));

  @Override
  public Set<String> getSupportedTypes() {
    return types;
  }

  @Override
  public boolean canCreatePublisher(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public CertPublisher newPublisher(String type) throws GenerationException {
    if (TYPE.equalsIgnoreCase(type)) {
      return new OcspCertPublisher();
    } else {
      throw new GenerationException("unknown publisher type " + type);
    }
  }

}
