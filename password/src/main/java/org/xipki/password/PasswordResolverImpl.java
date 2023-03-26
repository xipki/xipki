// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * An implementation of {@link PasswordResolver}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class PasswordResolverImpl implements PasswordResolver {

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
      return;
    }

    resolvers.remove(resolver);
    resolvers.add(resolver);
  } // method registResolver

  public void unregistResolver(SinglePasswordResolver resolver) {
    //might be null if dependency is optional
    if (resolver == null) {
      return;
    }

    try {
      resolvers.remove(resolver);
    } catch (Exception ex) {
    }
  } // method unregistResolver

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
    Args.notNull(protocol, "protocol");
    Args.notNull(password, "password");

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
