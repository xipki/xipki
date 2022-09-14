/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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
import org.xipki.util.StringUtil;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Keypool based keypair generator.
 *
 * @since 6.0.0
 * @author Lijun Liao
 */

public class KeypoolKeypairGenerator extends KeypairGenerator {

  static class CipherData {
    int encAlg;
    byte[] encMeta;
    byte[] cipherText;
  }

  private static final Logger LOG = LoggerFactory.getLogger(KeypoolKeypairGenerator.class);

  private int shardId;

  private KeypoolQueryExecutor queryExecutor;

  private SecretKey aes128key;

  private SecretKey aes192key;

  private SecretKey aes256key;

  private Cipher cipher;

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

    String password = conf.value("password");
    if (StringUtil.isBlank(password)) {
      throw new IllegalArgumentException("property password not defined");
    }

    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      char[] passwordChars = password.toCharArray();

      int[] keyLengths = {128, 192, 256};
      for (int keyLength : keyLengths) {
        KeySpec spec = new PBEKeySpec(passwordChars, "ENC".getBytes(StandardCharsets.UTF_8), 10000, keyLength);
        SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        if (keyLength == 128) {
          aes128key = key;
        } else if (keyLength == 192) {
          aes192key = key;
        } else {
          aes256key = key;
        }
      }

      cipher = Cipher.getInstance("AES/GCM/NoPadding");
    } catch (Exception ex) {
      throw new IllegalStateException("could not initialize Cipher", ex);
    }

  }

  @Override
  public synchronized PrivateKeyInfo generateKeypair(String keyspec)
      throws XiSecurityException {
    Integer keyspecId = keyspecToId.get(keyspec);
    if (keyspecId == null) {
      return null;
    }

    CipherData cd ;
    synchronized (keyspecId) {
      // need to synchronize to prevent from the reuse of the same keypair.
      try {
        cd = queryExecutor.nextKeyData(keyspecId);
      } catch (DataAccessException ex) {
        throw new XiSecurityException(ex);
      }
    }

    if (cd == null) {
      throw new XiSecurityException("found no keypair of spec " + keyspec + " in the keypool");
    }

    GCMParameterSpec spec = new GCMParameterSpec(128, cd.encMeta);
    SecretKey key;
    if (cd.encAlg == 1) {
      key = aes128key;
    } else if (cd.encAlg == 2) {
      key = aes192key;
    } else if (cd.encAlg == 3) {
      key = aes256key;
    } else {
      throw new XiSecurityException("unknown encryption algorithm " + cd.encAlg);
    }

    byte[] plain;
    try {
      cipher.init(Cipher.DECRYPT_MODE, key, spec);
      plain = cipher.doFinal(cd.cipherText);
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
             | InvalidAlgorithmParameterException ex) {
      throw new XiSecurityException("error decrypting ciphertext", ex);
    }
    return PrivateKeyInfo.getInstance(plain);
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
    } catch (DataAccessException | PasswordResolverException | IOException | RuntimeException ex) {
      throw new XiSecurityException(
          ex.getClass().getName() + " while parsing datasource " + datasourceName + ": " + ex.getMessage(), ex);
    }
  } // method loadDatasource

}
