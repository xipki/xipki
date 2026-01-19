// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileFactory;
import org.xipki.util.extra.exception.ObjectCreationException;

import java.util.Collections;
import java.util.Set;

/**
 * CertprofileFactory for the Certprofile of type 'json'.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class CertprofileFactoryImpl implements CertprofileFactory {

  private static final String TYPE = "xijson";
  private static final Set<String> types =
      Set.copyOf(Collections.singletonList(TYPE));

  @Override
  public Set<String> getSupportedTypes() {
    return types;
  }

  @Override
  public boolean canCreateProfile(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public Certprofile newCertprofile(String type)
      throws ObjectCreationException {
    if (TYPE.equalsIgnoreCase(type)) {
      return new XijsonCertprofile();
    } else {
      throw new ObjectCreationException(
          "unknown certprofile type '" + type + "'");
    }
  }

}
