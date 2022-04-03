/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.security.pkcs12;

import org.xipki.security.*;
import org.xipki.util.ObjectCreationException;

import java.util.*;

/**
 * {@link KeypairGeneratorFactory} for the type software.
 *
 * @author Lijun Liao
 * @since 5.4.0
 */

public class SoftwareKeypairGeneratorFactory implements KeypairGeneratorFactory {

  private static final String TYPE_SOFTWARE = "software";

  private static final Set<String> types = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList(TYPE_SOFTWARE)));

  private SecurityFactory securityFactory;

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  @Override
  public Set<String> getSupportedKeypairTypes() {
    return types;
  }

  @Override
  public boolean canCreateKeypairGenerator(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public KeypairGenerator newKeypairGenerator(String type, String conf,
                                              SecurityFactory securityFactory)
          throws ObjectCreationException {
    if (!canCreateKeypairGenerator(type)) {
      throw new ObjectCreationException("unknown keypair generator type " + type);
    }
    return new SoftwareKeypairGenerator(securityFactory.getRandom4Key());
  }

}
