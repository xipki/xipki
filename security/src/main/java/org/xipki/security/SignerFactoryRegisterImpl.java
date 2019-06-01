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

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.Args;
import org.xipki.util.ObjectCreationException;

/**
 * An implementation of {@link SignerFactoryRegister}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerFactoryRegisterImpl implements SignerFactoryRegister {

  private static final Logger LOG = LoggerFactory.getLogger(SignerFactoryRegisterImpl.class);

  private ConcurrentLinkedDeque<SignerFactory> factories = new ConcurrentLinkedDeque<>();

  public SignerFactoryRegisterImpl() {
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    Set<String> types = new HashSet<>();
    for (SignerFactory service : factories) {
      types.addAll(service.getSupportedSignerTypes());
    }
    return Collections.unmodifiableSet(types);
  }

  public void registFactory(SignerFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("registFactory invoked with null.");
      return;
    }

    boolean replaced = factories.remove(factory);
    factories.add(factory);

    String action = replaced ? "replaced" : "added";
    LOG.info("{} SignerFactory binding for {}", action, factory);
  }

  public void unregistFactory(SignerFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("unregistFactory invoked with null.");
      return;
    }

    if (factories.remove(factory)) {
      LOG.info("removed SignerFactory binding for {}", factory);
    } else {
      LOG.info("no SignerFactory binding found to remove for '{}'", factory);
    }
  }

  @Override
  public ConcurrentContentSigner newSigner(SecurityFactory securityFactory, String type,
      SignerConf conf, X509Certificate[] certificateChain) throws ObjectCreationException {
    Args.notBlank(type, "type");

    for (SignerFactory service : factories) {
      if (service.canCreateSigner(type)) {
        return service.newSigner(type, conf, certificateChain);
      }
    }

    throw new ObjectCreationException("could not find Factory to create Signer of type " + type);
  }

  @Override
  public void refreshTokenForSignerType(String signerType) throws XiSecurityException {
    for (SignerFactory service : factories) {
      if (service.canCreateSigner(signerType)) {
        service.refreshToken(signerType);
        break;
      }
    }
  }

}
