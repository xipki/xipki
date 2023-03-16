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

package org.xipki.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentLinkedQueue;

import static org.xipki.util.Args.notNull;

/**
 * An implementation of {@link PasswordResolver}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordResolverImpl implements PasswordResolver {

  private static final Logger LOG = LoggerFactory.getLogger(PasswordResolverImpl.class);

  private final ConcurrentLinkedQueue<SinglePasswordResolver> resolvers = new ConcurrentLinkedQueue<>();

  private boolean initialized = false;
  private String masterPasswordCallback;

  private int masterPasswordIterationCount = 2000;

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
  } // method init

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
  } // method registResolver

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
  } // method unregistResolver

  @Override
  public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
    notNull(passwordHint, "passwordHint");
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

    if (OBFPasswordService.PROTOCOL_OBF.equalsIgnoreCase(protocol)
        || PBEPasswordService.PROTOCOL_PBE.equalsIgnoreCase(protocol)) {
      throw new PasswordResolverException("could not find password resolver to resolve password "
          + "of protocol '" + protocol + "'");
    } else {
      return passwordHint.toCharArray();
    }
  } // method resolvePassword

  @Override
  public String protectPassword(String protocol, char[] password) throws PasswordResolverException {
    notNull(protocol, "protocol");
    notNull(password, "password");

    for (SinglePasswordResolver resolver : resolvers) {
      if (resolver.canResolveProtocol(protocol)) {
        return resolver.protectPassword(password);
      }
    }

    throw new PasswordResolverException("could not find password resolver to protect password "
        + "of protocol '" + protocol + "'");
  } // method protectPassword

  public void setMasterPasswordCallback(String masterPasswordCallback) {
    this.masterPasswordCallback = masterPasswordCallback;
  }

  public int getMasterPasswordIterationCount() {
    return masterPasswordIterationCount;
  }

  public void setMasterPasswordIterationCount(int masterPasswordIterationCount) {
    this.masterPasswordIterationCount = masterPasswordIterationCount;
  }
}
