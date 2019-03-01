/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security;

import java.io.Closeable;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Providers implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(Providers.class);

  public void init() {
    addBcProvider();
  }

  @Override
  public void close() {
  }

  private void addBcProvider() {
    final String provName = "BC";
    if (Security.getProvider(provName) != null) {
      LOG.info("security provider {} already initialized by other service", provName);
      return;
    }
    Security.addProvider(new BouncyCastleProvider());
  }

}
