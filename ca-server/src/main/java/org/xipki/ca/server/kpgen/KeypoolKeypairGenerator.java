// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.kpgen;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.DataSourceMap;
import org.xipki.ca.api.kpgen.KeypairGenerator;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Keypool based keypair generator.
 *
 * @since 6.0.0
 * @author Lijun Liao (xipki)
 */

public class KeypoolKeypairGenerator extends KeypairGenerator {

  private static class CipherData {
    int encAlg;
    byte[] encMeta;
    byte[] cipherText;
  }

  /**
   * XiPKI Keypool database query executor.
   *
   * @author Lijun Liao (xipki)
   * @since 6.0.0
   */

  private static class KeypoolQueryExecutor {

    private static final Logger LOG = LoggerFactory.getLogger(KeypoolQueryExecutor.class);

    private final DataSourceWrapper datasource;

    private final String sqlGetKeyData;

    KeypoolQueryExecutor(DataSourceWrapper datasource, int shardId) {
      this.datasource = Args.notNull(datasource, "datasource");
      this.sqlGetKeyData = datasource.buildSelectFirstSql(1,
          "ID,ENC_ALG,ENC_META,DATA FROM KEYPOOL WHERE SHARD_ID=" + shardId + " AND KID=?");
    } // constructor

    Map<String, Integer> getKeyspecs() throws DataAccessException {
      final String sql = "SELECT ID,KEYSPEC FROM KEYSPEC";
      PreparedStatement ps = datasource.prepareStatement(sql);
      ResultSet rs = null;

      Map<String, Integer> rv = new HashMap<>();

      try {
        rs = ps.executeQuery();
        while (rs.next()) {
          rv.put(rs.getString("KEYSPEC").toUpperCase(Locale.ROOT), rs.getInt("ID"));
        }

        return rv;
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(ps, rs);
      }
    } // method initIssuerStore

    KeypoolKeypairGenerator.CipherData nextKeyData(int keyspecId) throws DataAccessException {
      final String sql = sqlGetKeyData;
      PreparedStatement ps = datasource.prepareStatement(sql);

      ResultSet rs = null;
      try {
        ps.setInt(1, keyspecId);
        rs = ps.executeQuery();
        if (!rs.next()) {
          return null;
        }

        int id = rs.getInt("ID");
        KeypoolKeypairGenerator.CipherData cd = new KeypoolKeypairGenerator.CipherData();
        cd.encAlg = rs.getInt("ENC_ALG");
        cd.encMeta = org.xipki.util.Base64.decodeFast(rs.getString("ENC_META"));
        cd.cipherText = Base64.decodeFast(rs.getString("DATA"));
        datasource.releaseResources(ps, rs);
        ps = null;
        rs = null;

        final String sqlDeleteKeyData = "DELETE FROM KEYPOOL WHERE ID=?";
        ps = datasource.prepareStatement(sqlDeleteKeyData);
        ps.setInt(1, id);
        ps.executeUpdate();
        return cd;
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(ps, rs);
      }
    } // method nextKeyData

    boolean isHealthy() {
      final String sql = "SELECT ID FROM KEYSPEC";

      try {
        ResultSet rs = null;
        PreparedStatement ps = datasource.prepareStatement(sql);

        try {
          rs = ps.executeQuery();
        } finally {
          datasource.releaseResources(ps, rs);
        }
        return true;
      } catch (Exception ex) {
        LogUtil.error(LOG, ex);
        return false;
      }
    } // method isHealthy

  }

  private int shardId;

  private KeypoolQueryExecutor queryExecutor;

  private SecretKey aes128key;

  private SecretKey aes192key;

  private SecretKey aes256key;

  private Cipher cipher;

  private DataSourceMap datasources;

  private final Map<String, Integer> keyspecToId = new HashMap<>();

  public void setShardId(int shardId) {
    this.shardId = shardId;
  }

  public int getShardId() {
    return shardId;
  }

  public void setDatasources(DataSourceMap datasources) {
    this.datasources = datasources;
  }

  @Override
  protected void initialize0(ConfPairs conf) throws XiSecurityException {
    Args.notNull(conf, "conf");

    String datasourceName = conf.value("datasource");
    DataSourceWrapper datasource = null;
    if (datasourceName != null) {
      datasource = datasources.getDataSource(datasourceName);
    }

    if (datasource == null) {
      throw new XiSecurityException("no datasource named '" + datasourceName + "' is specified");
    }

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
  }

}
