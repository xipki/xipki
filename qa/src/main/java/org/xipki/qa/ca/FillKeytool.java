// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.EdECConstants;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Clock;
import java.util.*;

/**
 * Fill the keypool with keypairs.
 *
 * @since 6.0.0
 * @author Lijun Liao (xipki)
 */

public class FillKeytool implements AutoCloseable {

  private static final int ENCALG_AES128GCM = 1;

  private static final int ENCALG_AES192GCM = 2;

  private static final int ENCALG_AES256GCM = 3;

  protected final DataSourceWrapper datasource;

  public FillKeytool(DataSourceFactory datasourceFactory, String dbConfFile)
      throws InvalidConfException, IOException {
    try (InputStream dbConfStream = Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile)))) {
      this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, dbConfStream);
    }
  }

  @Override
  public void close() {
    if (datasource != null) {
      datasource.close();
    }
  }

  public void execute(int numKeypairs, String encAlg, char[] password) throws Exception {
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

    KeySpec spec = new PBEKeySpec(password, "ENC".getBytes(StandardCharsets.UTF_8), 10000, keyLength);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

    Connection conn = datasource.getConnection();

    PreparedStatement ps = null;
    String sql = null;
    try {
      sql = "DELETE FROM KEYPOOL";
      datasource.createStatement(conn).executeUpdate(sql);

      sql = "DELETE FROM KEYSPEC";
      datasource.createStatement(conn).executeUpdate(sql);

      // EC
      ASN1ObjectIdentifier[] curves = {
          SECObjectIdentifiers.secp256r1,             SECObjectIdentifiers.secp384r1,
          SECObjectIdentifiers.secp521r1,             TeleTrusTObjectIdentifiers.brainpoolP256r1,
          TeleTrusTObjectIdentifiers.brainpoolP384r1, TeleTrusTObjectIdentifiers.brainpoolP512r1,
          GMObjectIdentifiers.sm2p256v1,
      };

      List<String> keyspecs = new LinkedList<>(Arrays.asList("DSA/1024/160", "DSA/2048/224", "DSA/2048/256",
          "DSA/3072/256", "RSA/2048", "RSA/3072", "RSA/4096", "ED25519", "ED448", "X25519", "X448"));

      for (ASN1ObjectIdentifier curve : curves) {
        keyspecs.add("EC/" + curve.getId());
      }

      Map<String, Integer> keyspecToIdMap = new HashMap<>();

      int incrementKid = 1;
      for (String keyspec : keyspecs) {
        keyspecToIdMap.put(keyspec, incrementKid++);
      }

      sql = "INSERT INTO KEYSPEC (ID,KEYSPEC) VALUES (?,?)";
      ps = datasource.prepareStatement(sql);
      for (String keyspec : keyspecs) {
        int kid = keyspecToIdMap.get(keyspec);
        ps.setInt(1, kid);
        ps.setString(2, keyspec);
        ps.addBatch();
      }
      ps.executeBatch();

      ps = null;

      sql = "INSERT INTO KEYPOOL (ID,KID,SHARD_ID,ENC_ALG,ENC_META,DATA) VALUES(?,?,?,?,?,?)";

      SecureRandom rnd = new SecureRandom();
      ps = datasource.prepareStatement(sql);
      int id = 1;

      // loading the RSA pre-generated keypairs
      String[] rsaKeyspecs = {"RSA/2048", "RSA/3072", "RSA/4096"};
      Map<String, List<byte[]>> rsaKeysMap = new HashMap<>();
      for (String keyspec : rsaKeyspecs) {
        String fn = "/keypool/" + keyspec.replace('/', '_') + ".txt";

        try (InputStream in = FillKeytool.class.getResourceAsStream(fn)) {
          if (in != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            List<byte[]> keys = new ArrayList<>(100);
            rsaKeysMap.put(keyspec, keys);
            String line;
            while ((line = reader.readLine()) != null) {
              if (StringUtil.isNotBlank(line)) {
                keys.add(Base64.decodeFast(line));
              }
            }
          }
        }
      }

      for (String keyspec : keyspecs) {
        int kid = keyspecToIdMap.get(keyspec);

        String[] tokens = keyspec.split("/");
        String name = keyspec;
        if (tokens[0].equalsIgnoreCase("EC")) {
          String curveName = AlgorithmUtil.getCurveName(new ASN1ObjectIdentifier(tokens[1]));
          name += " (" + curveName + ")";
        }

        System.out.println(name + ":");
        boolean rsa = keyspec.startsWith("RSA/");
        System.out.println("\t" + (rsa ? "loading " : "generating ") + numKeypairs + " keypairs");
        long start = Clock.systemUTC().millis();

        List<byte[]> rsaKeys = null;
        if (rsa) {
          rsaKeys = rsaKeysMap.get(keyspec);
        }

        for (int i = 0; i < numKeypairs; i++) {
          byte[] keyInfo;
          if (rsa) {
            keyInfo = rsaKeys.get(i % rsaKeys.size());
          } else {
            keyInfo = generateKeypair(keyspec, rnd).getEncoded();
          }

          byte[] nonce = new byte[12];
          rnd.nextBytes(nonce);
          GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);

          cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
          byte[] encryptedData = cipher.doFinal(keyInfo);

          int idx = 1;
          ps.setInt(idx++, id++);
          ps.setInt(idx++, kid);
          ps.setInt(idx++, 0); // SHARD_ID
          ps.setInt(idx++, encAlgCode); // AES128/GCM
          ps.setString(idx++, Base64.encodeToString(nonce));
          ps.setString(idx, Base64.encodeToString(encryptedData));
          ps.addBatch();

          if ((i == numKeypairs - 1) || (i % 100 == 0)) {
            ps.executeBatch();
          }
        } // end for
        long duration = Clock.systemUTC().millis() - start;
        System.out.println("\t" + (rsa ? "loaded " : "generated ")
            + numKeypairs + " keypairs, took " + duration + " ms");
      } // end for
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null, false);
      datasource.returnConnection(conn);
    }
  }

  private static PrivateKeyInfo generateKeypair(String keyspec, SecureRandom random)
      throws Exception {
    String[] tokens = keyspec.split("/");
    String type = tokens[0];

    switch (type) {
      case "RSA": {
        int keysize = Integer.parseInt(tokens[1]);
        if (keysize > 4096) {
          throw new XiSecurityException("keysize too large");
        }

        KeyPair kp = KeyUtil.generateRSAKeypair(keysize, null, random);
        return KeyUtil.toPrivateKeyInfo((RSAPrivateCrtKey) kp.getPrivate());
      }
      case "EC": {
        ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(tokens[1]);

        KeyPair kp = KeyUtil.generateECKeypair(curveOid, random);
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        int orderBitLength = pub.getParams().getOrder().bitLength();

        byte[] publicKey = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), orderBitLength);

        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        return new PrivateKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid),
            new org.bouncycastle.asn1.sec.ECPrivateKey(
                orderBitLength, priv.getS(), new DERBitString(publicKey), null));
      }
      case "DSA": {
        int pLength = Integer.parseInt(tokens[1]);
        int qLength = Integer.parseInt(tokens[2]);
        DSAParameterSpec spec = DSAParameterCache.getDSAParameterSpec(pLength, qLength, null);
        KeyPair kp = KeyUtil.generateDSAKeypair(spec, random);
        DSAParameter parameter = new DSAParameter(spec.getP(), spec.getQ(), spec.getG());
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

        byte[] publicKey = new ASN1Integer(((DSAPublicKey) kp.getPublic()).getY()).getEncoded();

        // DSA private keys are represented as BER-encoded ASN.1 type INTEGER.
        DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();
        return new PrivateKeyInfo(algId, new ASN1Integer(priv.getX()), null, publicKey);
      }
      case "ED25519":
      case "ED448":
      case "X25519":
      case "X448": {
        ASN1ObjectIdentifier curveId = EdECConstants.getCurveOid(keyspec);
        KeyPair kp = KeyUtil.generateEdECKeypair(curveId, random);
        return PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
      }
      default: {
        throw new IllegalArgumentException("unknown keyspec " + keyspec);
      }
    }
  }

}
