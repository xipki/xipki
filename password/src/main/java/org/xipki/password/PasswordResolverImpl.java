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

package org.xipki.password;

import java.util.concurrent.ConcurrentLinkedQueue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordResolverImpl implements PasswordResolver {

  private static final Logger LOG = LoggerFactory.getLogger(PasswordResolverImpl.class);

  private ConcurrentLinkedQueue<SinglePasswordResolver> resolvers =
      new ConcurrentLinkedQueue<>();

  private boolean initialized = false;
  private String masterPasswordCallback;

  public PasswordResolverImpl() {
  }

  public void init() {
    if (initialized) {
      return;
    }

    resolvers.add(new SinglePasswordResolver.OBF());

    SinglePasswordResolver.PBE pbe = new SinglePasswordResolver.PBE();
    if (masterPasswordCallback != null) {
      pbe.setMasterPasswordCallback(masterPasswordCallback);
    }
    resolvers.add(pbe);
    initialized = true;
  }

  public void registResolver(SinglePasswordResolver resolver) {
    //might be null if dependency is optional
    if (resolver == null) {
      LOG.debug("registResolver invoked with null.");
      return;
    }

    boolean replaced = resolvers.remove(resolver);
    resolvers.add(resolver);
    String txt = replaced ? "replaced" : "added";
    LOG.debug("{} SinglePasswordResolver binding for {}", txt, resolver);
  }

  public void unregistResolver(SinglePasswordResolver resolver) {
    //might be null if dependency is optional
    if (resolver == null) {
      LOG.debug("unregistResolver invoked with null.");
      return;
    }

    try {
      if (resolvers.remove(resolver)) {
        LOG.debug("removed SinglePasswordResolver binding for {}", resolver);
      } else {
        LOG.debug("no SinglePasswordResolver binding found to remove for '{}'", resolver);
      }
    } catch (Exception ex) {
      LOG.debug("caught Exception({}). service is probably destroyed.", ex.getMessage());
    }
  }

  @Override
  public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
    Args.notNull(passwordHint, "passwordHint");
    int index = passwordHint.indexOf(':');
    if (index == -1) {
      return passwordHint.toCharArray();
    }

    String protocol = passwordHint.substring(0, index);

    for (SinglePasswordResolver resolver : resolvers) {
      if (resolver.canResolveProtocol(protocol)) {
        return resolver.resolvePassword(passwordHint);
      }
    }

    throw new PasswordResolverException("could not find password resolver to resolve password "
        + "of protocol '" + protocol + "'");
  }

  @Override
  public String protectPassword(String protocol, char[] password) throws PasswordResolverException {
    Args.notNull(protocol, "protocol");
    Args.notNull(password, "password");

    for (SinglePasswordResolver resolver : resolvers) {
      if (resolver.canResolveProtocol(protocol)) {
        return resolver.protectPassword(password);
      }
    }

    throw new PasswordResolverException("could not find password resolver to protect password "
        + "of protocol '" + protocol + "'");
  }

  public void setMasterPasswordCallback(String masterPasswordCallback) {
    this.masterPasswordCallback = masterPasswordCallback;
  }

}
