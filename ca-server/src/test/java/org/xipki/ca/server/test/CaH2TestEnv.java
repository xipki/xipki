// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CaUris;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CertPublisherFactoryRegister;
import org.xipki.ca.server.CertprofileFactoryRegister;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.Base64;
import org.xipki.codec.util.ConfPairs;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.ScriptRunner;
import org.xipki.pkix.Securities;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.audit.Audits;
import org.xipki.util.password.Passwords;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.conf.Validity;
import org.xipki.util.misc.NameId;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * A CA system on in-memory H2 databases: the CA configuration database and the certificate
 * store, initialized with the SQL scripts of the distribution. It contains the root CA
 * {@link #CA_NAME} with the certificate profiles {@link #PROFILE_TLS}.
 *
 * @author Lijun Liao (xipki)
 */
public final class CaH2TestEnv implements AutoCloseable {

  public static final String CA_NAME = "rootca1";

  public static final String PROFILE_TLS = "tls-ec";

  public static final String SIG_ALGO = "SHA256withECDSA";

  private static final String SQL_DIR =
      "../assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/h2/";

  private final Path workDir;

  private final DataSourceWrapper caDatasource;

  private final DataSourceWrapper caconfDatasource;

  private final Securities securities;

  private final CaManagerImpl caManager;

  private final X509Cert caCert;

  public CaH2TestEnv() throws Exception {
    workDir = Files.createTempDirectory("xipki-ca-h2-test");
    Passwords.init(workDir.toString());
    Audits.init("noop", new ConfPairs(), workDir.toString());

    // the databases are kept until the JVM exits (DB_CLOSE_DELAY=-1), so that the CA system,
    // which opens its own connection pools, sees the same databases.
    String dbSuffix = UUID.randomUUID().toString().replace("-", "");
    Path caDbConf = writeDbConf("ca", "ca_" + dbSuffix);
    Path caconfDbConf = writeDbConf("caconf", "caconf_" + dbSuffix);
    caDatasource = createDatasource("ca-test", caDbConf);
    caconfDatasource = createDatasource("caconf-test", caconfDbConf);
    runScript(caDatasource, "ca-init.h2.sql");
    runScript(caconfDatasource, "caconf-init.h2.sql");

    securities = new Securities();
    securities.init(null, workDir.toString());

    caManager = new CaManagerImpl(workDir.toString());
    caManager.setSecurityFactory(securities.securityFactory());
    CertprofileFactoryRegister profileRegister = new CertprofileFactoryRegister();
    profileRegister.registFactory(new CertprofileFactoryImpl());
    caManager.setCertprofileFactoryRegister(profileRegister);
    caManager.setCertPublisherFactoryRegister(new CertPublisherFactoryRegister());
    caManager.setKeyPairGeneratorFactories(Collections.emptySet());
    caManager.setCaServerConf(CaServerConf.readConfFromFile(
        writeServerConf(caDbConf, caconfDbConf).toString()));
    caManager.startCaSystem();

    caManager.addCertprofile(profile("rootca"));
    caManager.addCertprofile(profile(PROFILE_TLS));
    caCert = caManager.generateRootCa(newCaEntry(), "rootca", "CN=" + CA_NAME + ",O=myorg,C=DE",
        "1", null, null);
    caManager.addCertprofileToCa(PROFILE_TLS, CA_NAME);
  }

  public CaManagerImpl caManager() {
    return caManager;
  }

  public X509Cert caCert() {
    return caCert;
  }

  public Securities securities() {
    return securities;
  }

  /** A new connection pool to the certificate store database. */
  public DataSourceWrapper caDatasource() {
    return caDatasource;
  }

  /** A new connection pool to the CA configuration database. */
  public DataSourceWrapper caconfDatasource() {
    return caconfDatasource;
  }

  @Override
  public void close() {
    caManager.close();
    caDatasource.close();
    caconfDatasource.close();
    securities.close();
  }

  private static CaEntry newCaEntry() throws Exception {
    // the dummy certificate in the keystore is replaced by the generated CA certificate
    KeystoreGenerationParameters params =
        new KeystoreGenerationParameters("CHANGEIT".toCharArray());
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256, params).keystore();
    String signerConf = "algo=" + SIG_ALGO + ",password=CHANGEIT,keystore=base64:"
        + Base64.encodeToString(keystore);

    BaseCaInfo base = new BaseCaInfo("pkcs12", new Permissions(PermissionConstants.ALL));
    base.setSnSize(20);
    base.setNextCrlNo(1);
    base.setNumCrls(30);
    base.setExpirationPeriod(365);
    base.setKeepExpiredCertDays(-1);
    base.setStatus(CaStatus.active);
    base.setValidityMode(ValidityMode.CUTOFF);
    base.setMaxValidity(Validity.getInstance("10y"));
    base.setCaUris(new CaUris(List.of("http://example.org/rootca1.der"),
        List.of("http://example.org/ocsp"), List.of("http://example.org/rootca1.crl"), null));
    base.setCrlControl(new CrlControl(
        "interval.hours=24,fullcrl.intervals=7,overlap=90d,interval.time=02:00"));
    base.setKeypairGenNames(List.of("software"));
    return new CaEntry(base, new NameId(null, CA_NAME), signerConf);
  }

  private static CertprofileEntry profile(String name) throws IOException {
    String resource = "/certprofile/certprofile-" + name + ".json";
    try (InputStream in = CaH2TestEnv.class.getResourceAsStream(resource)) {
      if (in == null) {
        throw new IOException("resource " + resource + " not found");
      }
      String conf = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      return new CertprofileEntry(new NameId(null, name), "xijson", conf);
    }
  }

  private Path writeDbConf(String name, String dbName) throws IOException {
    String conf = "dataSourceClassName = org.h2.jdbcx.JdbcDataSource\n"
        + "dataSource.url = jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1\n"
        + "dataSource.user = sa\n"
        + "dataSource.password = \n"
        + "autoCommit = true\n"
        + "maximumPoolSize = 5\n"
        + "minimumIdle = 1\n"
        + "transactionIsolation = TRANSACTION_READ_COMMITTED\n";
    Path file = workDir.resolve(name + "-db.properties");
    Files.writeString(file, conf);
    return file;
  }

  private Path writeServerConf(Path caDbConf, Path caconfDbConf) throws IOException {
    String conf = "{\n"
        + "  \"master\": true,\n"
        + "  \"noLock\": true,\n"
        + "  \"shardId\": 0,\n"
        + "  \"datasources\": [\n"
        + "    {\"name\": \"ca\", \"conf\": {\"file\": \"" + jsonPath(caDbConf) + "\"}},\n"
        + "    {\"name\": \"caconf\", \"conf\": {\"file\": \"" + jsonPath(caconfDbConf) + "\"}}\n"
        + "  ],\n"
        + "  \"audit\": {\"type\": \"noop\"}\n"
        + "}\n";
    Path file = workDir.resolve("ca.json");
    Files.writeString(file, conf);
    return file;
  }

  private static String jsonPath(Path path) {
    return path.toAbsolutePath().toString().replace("\\", "/");
  }

  private static DataSourceWrapper createDatasource(String name, Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return new DataSourceFactory().createDataSource(name, props);
  }

  private void runScript(DataSourceWrapper datasource, String scriptName) throws Exception {
    Path script = Paths.get(SQL_DIR, scriptName);
    if (!Files.exists(script)) {
      throw new IOException("SQL script " + script.toAbsolutePath() + " not found");
    }
    ScriptRunner.runScript(datasource, script.toString(),
        workDir.resolve(scriptName + ".log"), workDir.resolve(scriptName + ".error.log"));
  }

  /** Returns the instant in the given number of days, truncated to seconds. */
  public static Instant inDays(int days) {
    return Instant.now().plus(days, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
  }

}
