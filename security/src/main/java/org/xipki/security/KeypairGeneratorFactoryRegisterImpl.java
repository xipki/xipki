// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.Args;
import org.xipki.util.exception.ObjectCreationException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * An implementation of {@link KeypairGeneratorFactoryRegister}.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class KeypairGeneratorFactoryRegisterImpl implements KeypairGeneratorFactoryRegister {

  private static final Logger LOG = LoggerFactory.getLogger(KeypairGeneratorFactoryRegisterImpl.class);

  private final ConcurrentLinkedDeque<KeypairGeneratorFactory> factories = new ConcurrentLinkedDeque<>();

  public KeypairGeneratorFactoryRegisterImpl() {
  }

  @Override
  public Set<String> getSupportedGeneratorTypes() {
    Set<String> types = new HashSet<>();
    for (KeypairGeneratorFactory service : factories) {
      types.addAll(service.getSupportedKeypairTypes());
    }
    return Collections.unmodifiableSet(types);
  }

  public void registFactory(KeypairGeneratorFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("registFactory invoked with null.");
      return;
    }

    boolean replaced = factories.remove(factory);
    factories.add(factory);

    String action = replaced ? "replaced" : "added";
    LOG.info("{} KeypairGeneratorFactory binding for {}", action, factory);
  }

  public void unregistFactory(KeypairGeneratorFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("unregistFactory invoked with null.");
      return;
    }

    if (factories.remove(factory)) {
      LOG.info("removed KeypairGeneratorFactory binding for {}", factory);
    } else {
      LOG.info("no KeypairGeneratorFactory binding found to remove for '{}'", factory);
    }
  }

  @Override
  public KeypairGenerator newKeypairGenerator(SecurityFactory securityFactory, String type, String conf)
      throws ObjectCreationException {
    Args.notBlank(type, "type");

    for (KeypairGeneratorFactory service : factories) {
      if (service.canCreateKeypairGenerator(type)) {
        return service.newKeypairGenerator(type, conf, securityFactory);
      }
    }

    throw new ObjectCreationException("could not find Factory to create keypair generator of type " + type);
  }

}
