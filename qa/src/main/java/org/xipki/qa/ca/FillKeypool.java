// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.KeyInfoPair;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataSourceFactory;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.io.IoUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Fill the keypool with keypairs.
 *
 * @author Lijun Liao (xipki)
 */

public class FillKeypool implements AutoCloseable {

  private static final int ENCALG_AES128GCM = 1;

  private static final int ENCALG_AES192GCM = 2;

  private static final int ENCALG_AES256GCM = 3;

  protected final DataSourceWrapper datasource;

  public FillKeypool(DataSourceFactory datasourceFactory, String dbConfFile)
      throws InvalidConfException, IOException {
    try (InputStream dbConfStream = Files.newInputStream(
        Paths.get(IoUtil.expandFilepath(dbConfFile)))) {
      this.datasource = datasourceFactory.createDataSource(
          "ds-" + dbConfFile, dbConfStream);
    }
  }

  @Override
  public void close() {
    if (datasource != null) {
      datasource.close();
    }
  }

  public void execute(int numKeypairs, String encAlg, char[] password)
      throws Exception {
    Args.notNull(password, "password");

    int encAlgCode;
    int keyLength;
    if (encAlg == null || "AES128/GCM".equalsIgnoreCase(encAlg)) {
      encAlgCode = ENCALG_AES128GCM;
      keyLength = 128;
    } else if ("AES192/GCM".equalsIgnoreCase(encAlg)) {
      encAlgCode = ENCALG_AES192GCM;
      keyLength = 192;
    } else if ("AES256/GCM".equalsIgnoreCase(encAlg)) {
      encAlgCode = ENCALG_AES256GCM;
      keyLength = 256;
    } else {
      throw new IllegalArgumentException("invalid encAlg " + encAlg);
    }

    Connection conn = datasource.getConnection();
    PreparedStatement ps = null;
    Statement stmt = null;
    String sql = null;
    ResultSet rs = null;
    SecureRandom rnd = new SecureRandom();

    try {
      // PBE salt and iteration
      conn = datasource.getConnection();
      Map<String, String> dbSchema = datasource.getDbSchema(conn);

      Map<String, String> newDbSchema = new HashMap<>(2);
      byte[] salt;
      String b64Salt = dbSchema.get("PBE_SALT");
      if (b64Salt != null) {
        salt = Base64.decodeFast(b64Salt);
      } else {
        salt = new byte[20];
        rnd.nextBytes(salt);
        newDbSchema.put("PBE_SALT", Base64.encodeToString(salt));
      }

      String iterationStr = dbSchema.get("PBE_ITERATION");
      int iteration;
      if (iterationStr != null) {
        iteration = Integer.parseInt(iterationStr);
        if (iteration < 10000) {
          throw new XiSecurityException("Invalid PBE_ITERATION " + iteration);
        }
      } else {
        iteration = 100000;
        newDbSchema.put("PBE_ITERATION", Integer.toString(iteration));
      }

      if (!newDbSchema.isEmpty()) {
        datasource.addDbSchema(conn, newDbSchema);
      }

      stmt = conn.createStatement();

      PBEKeySpec spec = new PBEKeySpec(password, salt, iteration, keyLength);
      SecretKeyFactory factory = SecretKeyFactory.getInstance(
          "PBKDF2WithHmacSHA256");
      SecretKey key = new SecretKeySpec(
          factory.generateSecret(spec).getEncoded(), "AES");
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

      sql = "DELETE FROM KEYPOOL";
      stmt.executeUpdate(sql);

      sql = "DELETE FROM KEYSPEC";
      stmt.executeUpdate(sql);

      KeySpec[] keyspecs = KeySpec.values();

      Map<KeySpec, Integer> keyspecToIdMap = new HashMap<>();

      int incrementKid = 1;
      for (KeySpec keyspec : keyspecs) {
        keyspecToIdMap.put(keyspec, incrementKid++);
      }

      sql = "INSERT INTO KEYSPEC (ID,KEYSPEC) VALUES (?,?)";
      ps = datasource.prepareStatement(sql);
      for (KeySpec keyspec : keyspecs) {
        int kid = keyspecToIdMap.get(keyspec);
        ps.setInt(1, kid);
        ps.setString(2, keyspec.text());
        ps.addBatch();
      }
      ps.executeBatch();
      ps.close();
      ps = null;

      sql = "INSERT INTO KEYPOOL (ID,KID,SHARD_ID,ENC_ALG,ENC_META," +
          "DATA,PUKDATA) VALUES(?,?,?,?,?,?,?)";

      ps = datasource.prepareStatement(sql);
      int id = 1;

      // loading the RSA pre-generated keypairs
      Map<KeySpec, List<KeyInfoPair>> preKeysMap = new HashMap<>();
      for (KeySpec keyspec : KeySpec.values()) {
        String fn = "/keypool/" + keyspec.name() + ".txt";

        try (InputStream in = FillKeypool.class.getResourceAsStream(fn)) {
          if (in == null) {
            continue;
          }

          BufferedReader reader = new BufferedReader(new InputStreamReader(in));
          List<KeyInfoPair> keys = new ArrayList<>(10);
          preKeysMap.put(keyspec, keys);
          String line;
          while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
              continue;
            }

            StringTokenizer tokenizer = new StringTokenizer(line, ":");
            String b64Sk = tokenizer.nextToken();
            String b64Pk = tokenizer.nextToken();
            byte[] skBytes = Base64.decodeFast(b64Sk);
            byte[] pkBytes = Base64.decodeFast(b64Pk);
            PrivateKeyInfo skInfo = PrivateKeyInfo.getInstance(skBytes);
            SubjectPublicKeyInfo pkInfo =
                SubjectPublicKeyInfo.getInstance(pkBytes);
            keys.add(new KeyInfoPair(pkInfo, skInfo));
          }
        }
      }

      for (KeySpec keyspec : keyspecs) {
        int kid = keyspecToIdMap.get(keyspec);
        List<KeyInfoPair> preKeys = preKeysMap.get(keyspec);

        long start = Clock.systemUTC().millis();

        for (int i = 0; i < numKeypairs; i++) {
          KeyInfoPair keyInfoPair;
          if (preKeys != null) {
            keyInfoPair = preKeys.get(i % preKeys.size());
          } else {
            KeyPair kp = KeyUtil.generateKeypair(keyspec, rnd);
            keyInfoPair = new KeyInfoPair(kp);
          }

          byte[] nonce = new byte[12];
          rnd.nextBytes(nonce);
          GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);

          cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
          byte[] encryptedData = cipher.doFinal(
              keyInfoPair.getPrivate().getEncoded());

          int idx = 1;
          ps.setInt(idx++, id++);
          ps.setInt(idx++, kid);
          ps.setInt(idx++, 0); // SHARD_ID
          ps.setInt(idx++, encAlgCode); // AES128/GCM
          ps.setString(idx++, Base64.encodeToString(nonce));
          ps.setString(idx++, Base64.encodeToString(encryptedData));
          ps.setString(idx,   Base64.encodeToString(
                                  keyInfoPair.getPrivate().getEncoded()));
          ps.addBatch();

          if ((i == numKeypairs - 1) || (i % 100 == 0)) {
            ps.executeBatch();
          }
        } // end for

        long duration = Clock.systemUTC().millis() - start;
        System.out.println(keyspec.text() + ": " +
            (preKeys != null ? "loaded " : "generated ") +
            numKeypairs + " keypairs, took " + duration + " ms");
      } // end for
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, null, false);
      datasource.releaseResources(ps, null, false);
      datasource.returnConnection(conn);
    }
  }

}
