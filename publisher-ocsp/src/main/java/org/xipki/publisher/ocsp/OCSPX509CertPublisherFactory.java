package org.xipki.publisher.ocsp;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.xipki.ca.api.publisher.x509.X509CertPublisher;
import org.xipki.ca.api.publisher.x509.X509CertPublisherFactory;
import org.xipki.common.ObjectCreationException;

// CHECKSTYLE:SKIP
public class OCSPX509CertPublisherFactory implements X509CertPublisherFactory {
  
  private static final String TYPE = "ocsp";
  
  private static final Set<String> types = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList(TYPE)));

  @Override
  public Set<String> getSupportedTypes() {
    return types;
  }

  @Override
  public boolean canCreatePublisher(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public X509CertPublisher newPublisher(String type) throws ObjectCreationException {
    if (TYPE.equalsIgnoreCase(type)) {
      return new OcspCertPublisher();
    } else {
      throw new ObjectCreationException("unknown publisher type " + type);
    }
  }

}
