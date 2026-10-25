// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.codec.asn1.GenerationException;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileFactory;

import java.util.Collections;
import java.util.Set;

/**
 * Certprofile Factory Impl.
 *
 * @author Lijun Liao (xipki)
 */

public class CertprofileFactoryImpl implements CertprofileFactory {

  private static final String TYPE = "xijson";
  private static final Set<String> types = Set.copyOf(Collections.singletonList(TYPE));

  @Override
  public Set<String> getSupportedTypes() {
    return types;
  }

  @Override
  public boolean canCreateProfile(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public Certprofile newCertprofile(String type) throws GenerationException {
    if (TYPE.equalsIgnoreCase(type)) {
      return new XijsonCertprofile();
    } else {
      throw new GenerationException("unknown certprofile type '" + type + "'");
    }
  }

}
