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
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.EdECConstants;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.*;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.*;
import java.security.spec.DSAParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;

/**
 * Fill the keypool with keypairs.
 *
 * @since 5.4.0
 * @author Lijun Liao
 */

public class FillKeytool {

  protected final DataSourceWrapper datasource;

  public FillKeytool(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
                     String dbConfFile)
      throws PasswordResolverException, IOException {
    try (InputStream dbConfStream = new FileInputStream(IoUtil.expandFilepath(dbConfFile))) {
      this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, dbConfStream,
          passwordResolver);
    }
  }

  public void execute(int numKeypairs)
      throws Exception {
    Connection conn = datasource.getConnection();

    PreparedStatement ps = null;
    String sql = null;
    try {
      sql = "DELETE FROM KEYPOOL";
      datasource.createStatement(conn).executeUpdate(sql);

      sql = "DELETE FROM KEYSPEC";
      datasource.createStatement(conn).executeUpdate(sql);

      List<String> keyspecs = new LinkedList<>();

      // DSA
      keyspecs.add("DSA/1024/160");
      keyspecs.add("DSA/2048/224");
      keyspecs.add("DSA/2048/256");
      keyspecs.add("DSA/3072/256");

      // EDDSA/XDH
      keyspecs.add("ED25519");
      keyspecs.add("ED448");
      keyspecs.add("X25519");
      keyspecs.add("X448");

      // EC
      ASN1ObjectIdentifier[] curves = {
          SECObjectIdentifiers.secp256r1,
          SECObjectIdentifiers.secp384r1,
          SECObjectIdentifiers.secp521r1,
          TeleTrusTObjectIdentifiers.brainpoolP256r1,
          TeleTrusTObjectIdentifiers.brainpoolP384r1,
          TeleTrusTObjectIdentifiers.brainpoolP512r1,
          GMObjectIdentifiers.sm2p256v1,
      };

      for (ASN1ObjectIdentifier curve : curves) {
        keyspecs.add("EC/" + curve.getId());
      }

      // RSA
      keyspecs.add("RSA/2048");
      keyspecs.add("RSA/3072");
      keyspecs.add("RSA/4096");

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

      sql = "INSERT INTO KEYPOOL (ID,KID,SHARD_ID,DATA) VALUES(?,?,?,?)";

      SecureRandom rnd = new SecureRandom();
      ps = datasource.prepareStatement(sql);
      int id = 1;

      // loading the RSA pre-generated keypairs
      String[] rsaKeyspecs = {"RSA/2048", "RSA/3072", "RSA/4096"};
      Map<String, List<byte[]>> rsaKeysMap = new HashMap<>();
      for (String keyspec : rsaKeyspecs) {
        String fn = "/keypool/" + keyspec.replace('/', '_') + ".txt";

        try (InputStream in = FillKeytool.class.getResourceAsStream(fn)) {
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
        long start = System.currentTimeMillis();

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
          ps.setInt(1, id++);
          ps.setInt(2, kid);
          ps.setInt(3, 0);
          ps.setString(4, Base64.encodeToString(keyInfo));
          ps.addBatch();

          if ((i == numKeypairs - 1) || (i % 100 == 0)) {
            ps.executeBatch();
          }
        } // end for
        long duration = System.currentTimeMillis() - start;
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
        java.security.interfaces.RSAPublicKey rsaPubKey =
            (java.security.interfaces.RSAPublicKey) kp.getPublic();
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
