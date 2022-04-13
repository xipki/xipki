package org.xipki.ca.server.keypool;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.KeypairGenerator;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.FileOrValue;

import java.io.IOException;
import java.sql.Connection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Keypool based keypair generator.
 *
 * @since 5.4.0
 * @author Lijun Liao
 */

public class KeypoolKeypairGenerator extends KeypairGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(KeypoolKeypairGenerator.class);

  private int shardId;

  private KeypoolQueryExecutor queryExecutor;

  private Map<String, FileOrValue> datasourceConfs;

  private Map<String, Integer> keyspecToId = new HashMap<>();

  public void setShardId(int shardId) {
    this.shardId = shardId;
  }

  public int getShardId() {
    return shardId;
  }

  public KeypoolQueryExecutor getQueryExecutor() {
    return queryExecutor;
  }

  public void setQueryExecutor(KeypoolQueryExecutor queryExecutor) {
    this.queryExecutor = queryExecutor;
  }

  public Map<String, FileOrValue> getDatasourceConfs() {
    return datasourceConfs;
  }

  public void setDatasourceConfs(Map<String, FileOrValue> datasourceConfs) {
    this.datasourceConfs = datasourceConfs;
  }

  @Override
  protected void initialize0(ConfPairs conf, PasswordResolver passwordResolver)
      throws XiSecurityException {
    Args.notNull(conf, "conf");

    String datasourceName = conf.value("datasource");

    FileOrValue datasourceConf = null;
    if (datasourceName != null) {
      datasourceConf = datasourceConfs.get(datasourceName);
    }

    if (datasourceConf == null) {
      throw new XiSecurityException("no datasource named '" + datasourceName + "' is specified");
    }

    DataSourceWrapper datasource = loadDatasource(datasourceName, datasourceConf, passwordResolver);

    try {
      queryExecutor = new KeypoolQueryExecutor(datasource, shardId);
      keyspecToId.clear();
      keyspecToId.putAll(queryExecutor.getKeyspecs());

      Set<String> set = new HashSet<>();
      for (String m : keyspecs) {
        if (keyspecToId.containsKey(m)) {
          set.add(m);
        }
      }
      super.keyspecs.clear();
      super.keyspecs.addAll(set);
    } catch (DataAccessException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  @Override
  public PrivateKeyInfo generateKeypair(String keyspec)
      throws XiSecurityException {
    Integer keyspecId = keyspecToId.get(keyspec);
    if (keyspecId == null) {
      return null;
    }

    byte[] bytes ;
    synchronized (keyspecId) {
      // need to synchronize to prevent from the reuse of the same keypair.
      try {
        bytes = queryExecutor.nextKeyData(keyspecId);
      } catch (DataAccessException ex) {
        throw new XiSecurityException(ex);
      }
    }

    if (bytes == null) {
      throw new XiSecurityException("found no keypair of spec " + keyspec + "in the keypool");
    }
    return PrivateKeyInfo.getInstance(bytes);
  }

  @Override
  public boolean isHealthy() {
    return queryExecutor != null && queryExecutor.isHealthy();
  }

  @Override
  public void close() throws IOException {
    queryExecutor.close();
  }

  private static DataSourceWrapper loadDatasource(
      String datasourceName, FileOrValue datasourceConf, PasswordResolver passwordResolver)
      throws XiSecurityException {
    try {
      DataSourceWrapper datasource = new DataSourceFactory().createDataSource(
          datasourceName, datasourceConf, passwordResolver);

      // test the datasource
      Connection conn = datasource.getConnection();
      datasource.returnConnection(conn);

      LOG.info("loaded datasource.{}", datasourceName);
      return datasource;
    } catch (DataAccessException | PasswordResolverException | IOException
        | RuntimeException ex) {
      throw new XiSecurityException(
          ex.getClass().getName() + " while parsing datasource " + datasourceName + ": "
              + ex.getMessage(), ex);
    }
  } // method loadDatasource

}
