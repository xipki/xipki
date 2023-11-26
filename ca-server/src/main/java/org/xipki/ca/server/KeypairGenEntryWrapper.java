// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.ca.api.DataSourceMap;
import org.xipki.ca.api.kpgen.KeypairGenerator;
import org.xipki.ca.api.kpgen.KeypairGeneratorFactory;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.server.kpgen.KeypoolKeypairGenerator;
import org.xipki.ca.server.kpgen.P11KeypairGenerator;
import org.xipki.ca.server.kpgen.SoftwareKeypairGenerator;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.util.Args;
import org.xipki.util.exception.ObjectCreationException;

import java.util.Set;

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

  public void init(SecurityFactory securityFactory, P11CryptServiceFactory p11CryptServiceFactory,
                   Set<KeypairGeneratorFactory> factories,
                   int shardId, DataSourceMap dataSourceMap)
      throws ObjectCreationException {
    Args.notNull(securityFactory, "securityFactory");
    dbEntry.faulty(true);

    String type = dbEntry.getType();
    if ("KEYPOOL".equalsIgnoreCase(type)) {
      generator = new KeypoolKeypairGenerator();
      ((KeypoolKeypairGenerator) generator).setShardId(shardId);
      ((KeypoolKeypairGenerator) generator).setDatasources(dataSourceMap);
    } else if ("SOFTWARE".equalsIgnoreCase(type)) {
      generator = new SoftwareKeypairGenerator(securityFactory.getRandom4Key());
    } else if ("PKCS11".equalsIgnoreCase(type)) {
      generator = new P11KeypairGenerator(p11CryptServiceFactory);
    } else {
      for (KeypairGeneratorFactory factory : factories) {
        if (factory.canCreateKeypairGenerator(type)) {
          generator = factory.newKeypairGenerator(type, dbEntry.getConf(), securityFactory);
          break;
        }
      }

      if (generator == null) {
        throw new ObjectCreationException("unknown keypairGen type " + type);
      }
    }

    try {
      generator.initialize(dbEntry.getConf());
    } catch (XiSecurityException ex) {
      throw new ObjectCreationException("error initializing keypair generator " + dbEntry.getName(), ex);
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
