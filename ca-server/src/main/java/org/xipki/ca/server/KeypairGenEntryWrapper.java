// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.server.keypool.KeypoolKeypairGenerator;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.KeypairGenerator;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.exception.ObjectCreationException;

import java.util.Map;

/**
 * Wrapper of keypair generation database entry.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class KeypairGenEntryWrapper {

  private KeypairGenEntry dbEntry;

  private KeypairGenerator generator;

  public KeypairGenEntryWrapper() {
  }

  public void setDbEntry(KeypairGenEntry dbEntry) {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
  }

  public void init(SecurityFactory securityFactory, int shardId, Map<String, DataSourceWrapper> datasources)
      throws ObjectCreationException {
    Args.notNull(securityFactory, "securityFactory");
    dbEntry.faulty(true);
    if ("KEYPOOL".equalsIgnoreCase(dbEntry.getType())) {
      generator = new KeypoolKeypairGenerator();

      ((KeypoolKeypairGenerator) generator).setShardId(shardId);
      ((KeypoolKeypairGenerator) generator).setDatasources(datasources);

      try {
        generator.initialize(dbEntry.getConf(), securityFactory.getPasswordResolver());
      } catch (XiSecurityException ex) {
        throw new ObjectCreationException("error initializing keypair generator " + dbEntry.getName(), ex);
      }
    } else {
      generator = securityFactory.createKeypairGenerator(dbEntry.getType(), dbEntry.getConf());
    }

    generator.setName(dbEntry.getName());
    dbEntry.faulty(false);
  }

  public KeypairGenEntry getDbEntry() {
    return dbEntry;
  }

  public KeypairGenerator getGenerator() {
    return generator;
  }

  public boolean isHealthy() {
    return generator != null && generator.isHealthy();
  }

}
