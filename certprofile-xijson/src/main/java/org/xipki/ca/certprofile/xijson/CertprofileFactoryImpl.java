/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.certprofile.xijson;

import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileFactory;
import org.xipki.util.ObjectCreationException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * CertprofileFactory for the Certprofile of type 'xijson'.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertprofileFactoryImpl implements CertprofileFactory {

  private static final String TYPE = "xijson";
  private static final Set<String> types = Collections.unmodifiableSet(
      new HashSet<>(Collections.singletonList(TYPE)));

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
      throw new ObjectCreationException("unknown certprofile type '" + type + "'");
    }
  }

}
