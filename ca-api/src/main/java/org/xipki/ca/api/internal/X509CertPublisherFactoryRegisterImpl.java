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

package org.xipki.ca.api.internal;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.publisher.X509CertPublisher;
import org.xipki.ca.api.publisher.X509CertPublisherFactory;
import org.xipki.ca.api.publisher.X509CertPublisherFactoryRegister;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertPublisherFactoryRegisterImpl implements X509CertPublisherFactoryRegister {

  private static final Logger LOG = LoggerFactory.getLogger(
      X509CertPublisherFactoryRegisterImpl.class);

  private ConcurrentLinkedDeque<X509CertPublisherFactory> services =
      new ConcurrentLinkedDeque<X509CertPublisherFactory>();

  @Override
  public boolean canCreatePublisher(String type) {
    for (X509CertPublisherFactory service : services) {
      if (service.canCreatePublisher(type)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public X509CertPublisher newPublisher(String type) throws ObjectCreationException {
    ParamUtil.requireNonBlank("type", type);

    for (X509CertPublisherFactory service : services) {
      if (service.canCreatePublisher(type)) {
        return service.newPublisher(type);
      }
    }

    throw new ObjectCreationException("could not find factory to create Publisher of type " + type);
  }

  @Override
  public Set<String> getSupportedTypes() {
    Set<String> types = new HashSet<>();
    for (X509CertPublisherFactory service : services) {
      types.addAll(service.getSupportedTypes());
    }
    return Collections.unmodifiableSet(types);
  }

  public void bindService(X509CertPublisherFactory service) {
    //might be null if dependency is optional
    if (service == null) {
      LOG.info("bindService invoked with null.");
      return;
    }

    boolean replaced = services.remove(service);
    services.add(service);

    String action = replaced ? "replaced" : "added";
    LOG.info("{} X509CertPublisherFactory binding for {}", action, service);
  }

  public void unbindService(X509CertPublisherFactory service) {
    //might be null if dependency is optional
    if (service == null) {
      LOG.info("unbindService invoked with null.");
      return;
    }

    if (services.remove(service)) {
      LOG.info("removed X509CertPublisherFactory binding for {}", service);
    } else {
      LOG.info("no X509CertPublisherFactory binding found to remove for {}", service);
    }
  }

}
