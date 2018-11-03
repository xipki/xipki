/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.api.internal;

import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreFactory;
import org.xipki.ocsp.api.OcspStoreFactoryRegister;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspStoreFactoryRegisterImpl implements OcspStoreFactoryRegister {

  private static final Logger LOG = LoggerFactory.getLogger(
      OcspStoreFactoryRegisterImpl.class);

  private ConcurrentLinkedDeque<OcspStoreFactory> factories =
      new ConcurrentLinkedDeque<OcspStoreFactory>();

  @Override
  public OcspStore newOcspStore(String type) throws ObjectCreationException {
    ParamUtil.requireNonBlank("type", type);

    for (OcspStoreFactory service : factories) {
      if (service.canCreateOcspStore(type)) {
        LOG.info("found factory to create OcspStore of type '" + type + "'");
        return service.newOcspStore(type);
      }
    }

    throw new ObjectCreationException(
        "could not find factory to create OcspStore of type '" + type + "'");
  }

  public void registFactory(OcspStoreFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("registFactory invoked with null.");
      return;
    }

    boolean replaced = factories.remove(factory);
    factories.add(factory);

    String action = replaced ? "replaced" : "added";
    LOG.info("{} CertStatusStoreFactory binding for {}", action, factory);
  }

  public void unregistFactory(OcspStoreFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("unregistFactory invoked with null.");
      return;
    }

    if (factories.remove(factory)) {
      LOG.info("removed CertStatusStoreFactory binding for {}", factory);
    } else {
      LOG.info("no CertStatusStoreFactory binding found to remove for '{}'", factory);
    }
  }

}
