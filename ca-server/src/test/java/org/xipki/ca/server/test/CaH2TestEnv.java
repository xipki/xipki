// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.pkix.ca.CaUris;
import org.xipki.pkix.ca.ValidityMode;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CertPublisherFactoryRegister;
import org.xipki.ca.server.CertprofileFactoryRegister;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.publisher.OcspCertPublisherFactory;
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
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.conf.FileOrValue;
import org.xipki.util.conf.Validity;
import org.xipki.util.misc.NameId;
import org.xipki.util.password.Passwords;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

  /** The SQL scripts of the distribution, relative to the root of the repository. */
  private static final String SQL_DIR =
      "assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/h2/";

  private final Path workDir;

  private final DataSourceWrapper caDatasource;

  private final DataSourceWrapper caconfDatasource;

  private final Path caDbConf;

  private final Path caconfDbConf;

  /** Whether the server configuration contains the CT log key directory. */
  private final boolean withCtLog;

  /** Additional databases (e.g. ocsp, keypool) by name: their configuration files. */
  private final Map<String, Path> extraDbConfs = new LinkedHashMap<>();

  private final Securities securities;

  private final CaManagerImpl caManager;

  private final X509Cert caCert;

  public CaH2TestEnv() throws Exception {
    this(false);
  }

  /**
   * Creates the environment.
   *
   * @param ocspDatabase whether an OCSP database (schema ocsp-init) is created and registered
   *        in the CA system as datasource {@code ocsp}, e.g. for the OCSP publisher.
   */
  public CaH2TestEnv(boolean ocspDatabase) throws Exception {
    this(ocspDatabase ? new String[]{"ocsp"} : new String[0]);
  }

  /**
   * Creates the environment.
   *
   * @param extraDatabases names of additional databases, e.g. {@code ocsp}, {@code keypool}.
   *        Each is initialized with the SQL script {@code <name>-init.h2.sql} and registered in
   *        the CA system as datasource with this name.
   */
  public CaH2TestEnv(String... extraDatabases) throws Exception {
    this(List.of(), extraDatabases);
  }

  /**
   * Creates the environment with CT log public keys.
   *
   * @param ctLogPublicKeys files with the public keys of the CT logs (PEM or DER). If not empty,
   *        they are copied to the directory {@code ctlog} in the work directory, and the server
   *        configuration contains {@code "ctLog": {"keydir": "ctlog"}}.
   * @param extraDatabases see {@link #CaH2TestEnv(String...)}.
   */
  public CaH2TestEnv(List<Path> ctLogPublicKeys, String... extraDatabases) throws Exception {
    this(new Options().ctLogPublicKeys(ctLogPublicKeys).extraDatabases(extraDatabases));
  }

  /** Options of the environment. */
  public static final class Options {

    private List<Path> ctLogPublicKeys = List.of();

    private String[] extraDatabases = new String[0];

    private boolean pkcs11;

    /** See {@link #CaH2TestEnv(List, String...)}. */
    public Options ctLogPublicKeys(List<Path> ctLogPublicKeys) {
      this.ctLogPublicKeys = ctLogPublicKeys;
      return this;
    }

    /** See {@link #CaH2TestEnv(String...)}. */
    public Options extraDatabases(String... extraDatabases) {
      this.extraDatabases = extraDatabases;
      return this;
    }

    /**
     * With the PKCS#11 module {@link #P11_MODULE}: the in-memory HSM xihsm
     * ({@code xihsm:mem:vendor=xihsm}, user PIN {@link #P11_PIN}); requires the test
     * dependency {@code org.xipki.crypto:xihsm}. The CA system gets the
     * {@code P11CryptServiceFactory}, the signer type {@code pkcs11} is available.
     */
    public Options pkcs11(boolean pkcs11) {
      this.pkcs11 = pkcs11;
      return this;
    }

  }

  /** Name of the PKCS#11 module, see {@link Options#pkcs11(boolean)}. */
  public static final String P11_MODULE = "default";

  /** User PIN of the PKCS#11 module. */
  public static final String P11_PIN = "123456";

  /**
   * Creates the environment with the given options.
   *
   * @param options the options.
   */
  public CaH2TestEnv(Options options) throws Exception {
    List<Path> ctLogPublicKeys = options.ctLogPublicKeys;
    String[] extraDatabases = options.extraDatabases;
    workDir = Files.createTempDirectory("xipki-ca-h2-test");
    this.withCtLog = !ctLogPublicKeys.isEmpty();
    if (withCtLog) {
      Path keydir = Files.createDirectories(workDir.resolve("ctlog"));
      for (Path key : ctLogPublicKeys) {
        Files.copy(key, keydir.resolve(key.getFileName()));
      }
    }
    Passwords.init(workDir.toString());
    Audits.init("noop", new ConfPairs(), workDir.toString());

    // the databases are kept until the JVM exits (DB_CLOSE_DELAY=-1), so that the CA system,
    // which opens its own connection pools, sees the same databases.
    String dbSuffix = UUID.randomUUID().toString().replace("-", "");
    caDbConf = writeDbConf("ca", "ca_" + dbSuffix);
    caconfDbConf = writeDbConf("caconf", "caconf_" + dbSuffix);
    for (String name : extraDatabases) {
      extraDbConfs.put(name, writeDbConf(name, name + "_" + dbSuffix));
    }
    caDatasource = createDatasource("ca-test", caDbConf);
    caconfDatasource = createDatasource("caconf-test", caconfDbConf);
    runScript(caDatasource, "ca-init.h2.sql");
    runScript(caconfDatasource, "caconf-init.h2.sql");
    for (Map.Entry<String, Path> m : extraDbConfs.entrySet()) {
      try (DataSourceWrapper datasource = createDatasource(m.getKey() + "-init", m.getValue())) {
        runScript(datasource, m.getKey() + "-init.h2.sql");
      }
    }

    securities = new Securities();
    Securities.SecurityConf securityConf = null;
    if (options.pkcs11) {
      securityConf = new Securities.SecurityConf();
      securityConf.setPkcs11Conf(FileOrValue.ofValue("{\"modules\": [{\"name\": \"" + P11_MODULE
          + "\", \"readonly\": false, \"user\": \"CKU_USER\", \"numSessions\": 10,"
          + " \"includeSlots\": [{\"index\": 0}],"
          + " \"nativeLibraries\": [{\"path\": \"xihsm:mem:vendor=xihsm\"}],"
          + " \"passwordSets\": [{\"passwords\": [\"" + P11_PIN + "\"]}]}]}"));
    }
    securities.init(securityConf, workDir.toString());

    caManager = new CaManagerImpl(workDir.toString());
    caManager.setSecurityFactory(securities.securityFactory());
    caManager.setP11CryptServiceFactory(securities.p11CryptServiceFactory());
    CertprofileFactoryRegister profileRegister = new CertprofileFactoryRegister();
    profileRegister.registFactory(new CertprofileFactoryImpl());
    caManager.setCertprofileFactoryRegister(profileRegister);
    CertPublisherFactoryRegister publisherRegister = new CertPublisherFactoryRegister();
    publisherRegister.registFactory(new OcspCertPublisherFactory());
    caManager.setCertPublisherFactoryRegister(publisherRegister);
    caManager.setKeyPairGeneratorFactories(Collections.emptySet());
    caManager.setCaServerConf(CaServerConf.readConfFromFile(
        writeServerConf(caDbConf, caconfDbConf).toString()));
    caManager.startCaSystem();

    caManager.addCertprofile(profile("rootca"));
    caManager.addCertprofile(profile(PROFILE_TLS));
    caCert = caManager.generateRootCa(newCaEntry(), "rootca", "CN=" + CA_NAME + ",O=myorg,C=DE",
        "1", null, null).x509Cert();
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

  /** The configuration file of the certificate store database. */
  public Path caDbConf() {
    return caDbConf;
  }

  /** The configuration file of the CA configuration database. */
  public Path caconfDbConf() {
    return caconfDbConf;
  }

  /**
   * Creates a new, empty in-memory database with the schema of the certificate store
   * ({@code caconf == false}) or of the CA configuration ({@code caconf == true}).
   *
   * @return the configuration file of the database.
   */
  public Path newDatabase(String name, boolean caconf) throws Exception {
    return newDatabase(name, caconf ? "caconf-init.h2.sql" : "ca-init.h2.sql");
  }

  /**
   * Creates a new in-memory database, initialized with the given SQL script of the
   * distribution (e.g. {@code ocsp-cache-init.h2.sql}).
   *
   * @return the configuration file of the database.
   */
  public Path newDatabase(String name, String initScript) throws Exception {
    String dbSuffix = UUID.randomUUID().toString().replace("-", "");
    Path conf = writeDbConf(name, name + "_" + dbSuffix);
    try (DataSourceWrapper datasource = createDatasource(name, conf)) {
      runScript(datasource, initScript);
    }
    return conf;
  }

  /** The configuration file of the OCSP database, or {@code null}. */
  public Path ocspDbConf() {
    return extraDbConf("ocsp");
  }

  /** The configuration file of the additional database with the given name, or {@code null}. */
  public Path extraDbConf(String name) {
    return extraDbConfs.get(name);
  }

  /** The working directory of this environment (a temporary directory). */
  public Path workDir() {
    return workDir;
  }

  @Override
  public void close() {
    caManager.close();
    caDatasource.close();
    caconfDatasource.close();
    securities.close();
  }

  private static CaEntry newCaEntry() throws Exception {
    return newCaEntry(CA_NAME);
  }

  /**
   * A new CA entry with a new P-256 key in a PKCS#12 keystore (password CHANGEIT), as used
   * for {@link #CA_NAME}, to generate a further root CA.
   */
  public static CaEntry newCaEntry(String caName) throws Exception {
    // the CA certificate is generated (generateRootCa) and kept in the CA entry; the
    // keystore keeps its dummy certificate
    KeystoreGenerationParameters params =
        new KeystoreGenerationParameters("CHANGEIT".toCharArray());
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256, params).keystore();
    return newCaEntry(caName, "pkcs12", "algo=" + SIG_ALGO + ",password=CHANGEIT,keystore=base64:"
        + Base64.encodeToString(keystore));
  }

  /**
   * A new CA entry with the given signer, e.g. type {@code pkcs11} and configuration
   * {@code module=default,slot=0,key-label=ca1,algo=SHA256withECDSA}.
   */
  public static CaEntry newCaEntry(String caName, String signerType, String signerConf)
      throws Exception {
    BaseCaInfo base = new BaseCaInfo(signerType, new Permissions(PermissionConstants.ALL));
    base.setSnSize(20);
    base.setNextCrlNo(1);
    base.setNumCrls(30);
    base.setExpirationPeriod(365);
    base.setKeepExpiredCertDays(-1);
    base.setStatus(CaStatus.active);
    base.setValidityMode(ValidityMode.CUTOFF);
    base.setMaxValidity(Validity.getInstance("10y"));
    base.setCaUris(new CaUris(List.of("http://example.org/" + caName + ".der"),
        List.of("http://example.org/ocsp"), List.of("http://example.org/" + caName + ".crl"),
        null));
    base.setCrlControl(new CrlControl(
        "interval.hours=24,fullcrl.intervals=7,overlap=90d,interval.time=02:00"));
    base.setKeypairGenNames(List.of("software"));
    return new CaEntry(base, new NameId(null, caName), signerConf);
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
        + "    {\"name\": \"caconf\", \"conf\": {\"file\": \"" + jsonPath(caconfDbConf) + "\"}}"
        + extraDatasources()
        + "\n"
        + "  ],\n"
        + (withCtLog ? "  \"ctLog\": {\"keydir\": \"ctlog\"},\n" : "")
        + "  \"audit\": {\"type\": \"noop\"}\n"
        + "}\n";
    Path file = workDir.resolve("ca.json");
    Files.writeString(file, conf);
    return file;
  }

  private String extraDatasources() {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, Path> m : extraDbConfs.entrySet()) {
      sb.append(",\n    {\"name\": \"").append(m.getKey()).append("\", \"conf\": {\"file\": \"")
          .append(jsonPath(m.getValue())).append("\"}}");
    }
    return sb.toString();
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
    // the working directory is the module directory, e.g. ca-server or shells/ca-mgmt-shell:
    // the root of the repository is searched in its parents
    Path script = null;
    for (Path dir = Paths.get("").toAbsolutePath(); dir != null; dir = dir.getParent()) {
      Path candidate = dir.resolve(SQL_DIR).resolve(scriptName);
      if (Files.exists(candidate)) {
        script = candidate;
        break;
      }
    }
    if (script == null) {
      throw new IOException("SQL script " + SQL_DIR + scriptName + " not found in "
          + Paths.get("").toAbsolutePath() + " and its parents");
    }
    ScriptRunner.runScript(datasource, script.toString(),
        workDir.resolve(scriptName + ".log"), workDir.resolve(scriptName + ".error.log"));
  }

  /** Returns the instant in the given number of days, truncated to seconds. */
  public static Instant inDays(int days) {
    return Instant.now().plus(days, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
  }

}
