// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.demo;

import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileFactory;
import org.xipki.util.exception.ObjectCreationException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Factory to create certprofile of type demo-profiletype.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertprofileFactoryImpl implements CertprofileFactory {

  private static final String TYPE = "demo-profiletype";

  private static final Set<String> types = Collections.unmodifiableSet(new HashSet<>(Collections.singletonList(TYPE)));

  @Override
  public Set<String> getSupportedTypes() {
    return types;
  }

  @Override
  public boolean canCreateProfile(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public Certprofile newCertprofile(String type) throws ObjectCreationException {
    if (TYPE.equalsIgnoreCase(type)) {
      return new DemoCertprofile();
    } else {
      throw new ObjectCreationException("unknown certprofile type '" + type + "'");
    }
  }

}
