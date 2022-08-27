/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ocsp.server.store;

import org.bouncycastle.crypto.ExtendedDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.security.HashAlgo;
import org.xipki.security.asn1.CrlStreamParser;
import org.xipki.util.*;
import org.xipki.util.http.SslContextConf;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.util.Args.notNull;

/**
 * OcspStore for CRLs. Note that the CRLs will be imported to XiPKI OCSP database.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlDbCertStatusStore extends DbCertStatusStore {

  private class CrlUpdateService implements Runnable {

    @Override
    public void run() {
      try {
        updateStore();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "error while calling initializeStore() for store " + name);
      }
    }

  } // class CrlUpdateService

  private static class CompositeOutputStream extends OutputStream {

    private final ExtendedDigest digest;

    private byte[] hashValue;

    private final OutputStream outputStream;

    public CompositeOutputStream(HashAlgo hashAlgo, OutputStream outputStream) {
      this.digest = hashAlgo == null ? null : hashAlgo.createDigest();
      this.outputStream = outputStream;
    }

    @Override
    public void write(byte[] b) throws IOException {
      if (digest != null) {
        digest.update(b, 0, b.length);
      }
      outputStream.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      if (digest != null) {
        digest.update(b, off, len);
      }
      outputStream.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
      outputStream.flush();
    }

    @Override
    public void close() throws IOException {
      outputStream.close();
    }

    @Override
    public void write(int i) throws IOException {
      if (digest != null) {
        digest.update((byte) i);
      }
      outputStream.write(i);
    }

    public byte[] getHashValue() {
      if (digest == null) {
        return null;
      }
      if (hashValue == null) {
        byte[] t = new byte[digest.getDigestSize()];
        digest.doFinal(t, 0);
        this.hashValue = t;
      }
      return hashValue;
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(CrlDbCertStatusStore.class);

  private static final String CT_PKIX_CRL = "application/pkix-crl";

  private final CrlUpdateService storeUpdateService = new CrlUpdateService();

  private final Object lock = new Object();

  private final AtomicBoolean crlUpdateInProcess = new AtomicBoolean(false);

  private final ConcurrentHashMap<String, Curl> curls = new ConcurrentHashMap<>();

  private final ConcurrentHashMap<String, Long> curlsConfLastModified = new ConcurrentHashMap<>();

  private String dir;

  private int sqlBatchCommit;

  private boolean ignoreExpiredCrls;

  private boolean crlUpdated;

  private boolean firstTime = true;

  private Map<String, ?> sourceConf;

  /**
   * Initialize the store.
   *
   * @param sourceConf
   * the store source configuration. It contains following key-value pairs:
   * <ul>
   * <li>dir: required
   *   <p>
   *   Directory of the CRL resources.</li>
   * <li>sqlBatchCommit:
   *   <p>
   *   Number of SQL queries before next commit, default to be 1000.</li>
   * <li>ignoreExpiredCrls:
   *   <p>
   *   Whether expired CRLs are ignored, default to true.</li>
   * </ul>
   * @param datasource DataSource.
   */
  public void init(Map<String, ?> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException {
    this.sourceConf = notNull(sourceConf, "sourceConf");

    // check the dir
    this.dir = IoUtil.expandFilepath(getStrValue(sourceConf, "dir", true), true);
    File dirObj = new File(this.dir);
    if (!dirObj.exists()) {
      throw new OcspStoreException("the dir " + this.dir + " does not exist");
    }

    if (!dirObj.isDirectory()) {
      throw new OcspStoreException(this.dir + " is not a directory");
    }

    File[] subDirs = new File(dir).listFiles();
    boolean foundCrlDir = false;
    if (subDirs != null) {
      for (File subDir : subDirs) {
        if (!subDir.isDirectory()) {
          continue;
        }

        String dirName = subDir.getName();
        if (dirName.startsWith("crl-")) {
          foundCrlDir = true;
          break;
        }
      }
    }

    if (!foundCrlDir) {
      LOG.warn("Found no sub-directory starting with 'crl-' in " + dir);
    }

    String value = getStrValue(sourceConf, "sqlBatchCommit", false);
    this.sqlBatchCommit = StringUtil.isBlank(value) ? 1000 : Integer.parseInt(value);

    value = getStrValue(sourceConf, "ignoreExpiredCrls", false);
    this.ignoreExpiredCrls = StringUtil.isBlank(value) || Boolean.parseBoolean(value);

    super.datasource = datasource;

    value = getStrValue(sourceConf, "startupDelay", false);
    int startupDelaySeconds = value == null ? 5 : Integer.parseInt(value);
    // so that the ocsp service (tomcat) can start without blocking.
    Runnable runnable = () -> updateStore();
    ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1);
    executor.schedule(runnable, startupDelaySeconds, TimeUnit.SECONDS);
    executor.shutdown();
  } // method init

  private static String getStrValue(Map<String, ?> sourceConf, String confName, boolean mandatory) {
    Object objVal = sourceConf.get(confName);
    if (objVal == null) {
      if (mandatory) {
        throw new IllegalArgumentException("mandatory " + confName + " is not specified in sourceConf");
      } else {
        return null;
      }
    }

    if (objVal instanceof String) {
      return (String) objVal;
    } else {
      return objVal.toString();
    }
  } // method getStrValue

  @Override
  protected boolean isIgnoreExpiredCrls() {
    return ignoreExpiredCrls;
  }

  @Override
  protected List<Runnable> getScheduledServices() {
    return Collections.singletonList(storeUpdateService);
  }

  @Override
  protected boolean isInitialized() {
    return crlUpdated && super.isInitialized();
  }

  private void updateStore() {
    if (crlUpdateInProcess.get()) {
      return;
    }

    synchronized (lock) {
      crlUpdateInProcess.set(true);
      try {
        File[] subDirs = new File(dir).listFiles();
        boolean withValidSubDirs = false;
        if (subDirs != null) {
          for (File subDir : subDirs) {
            if (subDir.isDirectory() && subDir.getName().startsWith("crl-")) {
              new File(subDir, ".generated").mkdirs();
              withValidSubDirs = true;
            }
          }
        }

        if (!withValidSubDirs) {
          return;
        }

        // Download CRL
        List<File> downloadDirs = new ArrayList<>();
        for (File subDir : subDirs) {
          if (!(subDir.isDirectory() && subDir.getName().startsWith("crl-"))) {
            continue;
          }

          // CRL will not be downloaded by OCSP responder.
          if (!new File(subDir, "crl.download").exists()) {
            continue;
          }

          downloadDirs.add(subDir);
          try {
            downloadCrl(subDir);
          } catch (Exception ex) {
            LogUtil.error(LOG, ex, "error downloading CRL for path " + subDir.getPath());
          }
        }

        boolean updateMe = false;
        for (File subDir : subDirs) {
          if (!(subDir.isDirectory() && subDir.getName().startsWith("crl-"))) {
            continue;
          }

          boolean isDownloadDir = downloadDirs.contains(subDir);
          File dir = isDownloadDir ? new File(subDir, ".generated") : subDir;
          if (new File(dir, "UPDATEME").exists()) {
            updateMe = true;
            break;
          }
        }

        if (updateMe) {
          ImportCrl importCrl = new ImportCrl(datasource, dir, sqlBatchCommit, ignoreExpiredCrls);

          if (importCrl.importCrlToOcspDb()) {
            LOG.info("updated CertStore {} successfully", name);
          } else {
            LOG.error("updating CertStore {} failed", name);
          }
        } else {
          LOG.info("CertStore {} not changed", name);
        }

        if (firstTime) {
          super.init(sourceConf, datasource);
          firstTime = false;
        } else {
          if (updateMe) {
            super.updateIssuerStore(true);
          }
        }
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "error while executing updateStore()");
      } finally {
        crlUpdated = true;
        crlUpdateInProcess.set(false);
      }
    } // end lock
  } // method updateStore

  // Download CRL
  private void downloadCrl(File subDir) throws Exception {
    if (new File(subDir, "REMOVEME").exists()) {
      // CA is removed, no download will be processed.
      return;
    }

    Properties revocationProps = loadProperties(new File(subDir, "REVOCATION"));
    if (null != revocationProps.getProperty("ca.revocation.time")) {
      // CA is revoked, no download will be processed.
      return;
    }

    File generatedDir = new File(subDir, ".generated");

    File updatemeFile = new File(generatedDir, "UPDATEME");
    if (updatemeFile.exists()) {
      // the last CRL is waiting for the processing
      return;
    }

    File crlInfoFile = new File(generatedDir, "ca.crl.info");
    Date nextUpdate;
    BigInteger crlNumber = null;

    File crlDownloadFile = new File(subDir, "crl.download");
    File updateMeNowFile = new File(subDir, "UPDATEME_NOW");

    boolean downloadCrl = false;
    String hashAlgo = null;
    byte[] hashValue = null;
    if (!crlInfoFile.exists()) {
      // no CRL is available
      downloadCrl = true;
    } else if (updateMeNowFile.exists()) {
      // force download
      downloadCrl = true;
    } else {
      // Check if there exists fresher CRL
      Properties props = loadProperties(crlInfoFile);
      nextUpdate = DateUtil.parseUtcTimeyyyyMMddhhmmss(props.getProperty("nextupdate"));
      crlNumber = new BigInteger(props.getProperty("crlnumber"));
      String[] tokens = props.getProperty("hash").split(" ");
      hashAlgo = tokens[0];
      hashValue = Hex.decode(tokens[1]);

      props = loadProperties(crlDownloadFile);
      Validity validity = Validity.getInstance(props.getProperty("download.before.nextupdate"));
      if (validity.getValidity() < 1) {
        LOG.error("invalid download.before.nextupdate {}", validity);
      } else {
        if (validity.add(new Date()).after(nextUpdate)) {
          downloadCrl = true;
        }
      }
    }

    if (!downloadCrl) {
      return;
    }

    Properties props = loadProperties(crlDownloadFile);
    String downloadUrl = props.getProperty("download.url");
    if (downloadUrl == null) {
      downloadUrl = props.getProperty("crldp");
    }

    if (StringUtil.isBlank(downloadUrl)) {
      LOG.error("Neither download.url nor crldp in {} is specified, skip it", crlDownloadFile.getPath());
      return;
    }

    String str = props.getProperty("download.fp.url");

    String hashUrl = null;
    if (str != null) {
      String[] tokens = str.split(" ");
      if (hashValue != null && !hashAlgo.equalsIgnoreCase(tokens[0])) {
        // ignore the stored hash value
        hashValue = null;
      }
      hashAlgo = tokens[0];
      hashUrl = tokens[1];
    }

    String subDirPath = subDir.getPath();
    Curl curl = curls.get(subDirPath);

    File trustanchorFile = new File(subDir, "tls-trustanchor.pem");
    if (trustanchorFile.exists()) {
      if (curl != null) {
        long lastModified = curlsConfLastModified.get(subDirPath);
        if (trustanchorFile.lastModified() != lastModified) {
          curl = null;
          curlsConfLastModified.remove(subDirPath);
          curls.remove(subDirPath);
        }
      }

      if (curl == null) {
        SslContextConf sslContextConf = new SslContextConf();
        sslContextConf.setSslTrustanchors(trustanchorFile.getPath());
        curl = new DefaultCurl(sslContextConf);
        curls.put(subDirPath, curl);
        curlsConfLastModified.put(subDirPath, trustanchorFile.lastModified());
      }
    } else {
      if (curl == null) {
        curl = new DefaultCurl(null);
        curls.put(subDirPath, curl);
        curlsConfLastModified.put(subDirPath, 0L);
      }
    }

    // download the fingerprint if download.fp.url is specified
    if (hashUrl != null) {
      Curl.CurlResult downResult = curl.curlGet(hashUrl, false, null, null);
      if (downResult.getContentLength() > 0 && Arrays.equals(hashValue, downResult.getContent())) {
        LOG.info("Fingerprint of the CRL has not changed, skip downloading CRL");
        return;
      }
    }

    File tmpCrlFile = new File(generatedDir, "tmp-ca.crl");

    CompositeOutputStream crlStream = new CompositeOutputStream(
            hashAlgo == null ? null : HashAlgo.getInstance(hashAlgo),
            new FileOutputStream(tmpCrlFile));

    Curl.CurlResult downResult;
    try {
      downResult = curl.curlGet(downloadUrl, crlStream, false, null, null);
    } finally {
      crlStream.close();
    }
    String contentType = downResult.getContentType();

    if (!CT_PKIX_CRL.equals(contentType)) {
      LOG.error("Downloading CRL failed, expected content type {}, but received {}", CT_PKIX_CRL, contentType);
      return;
    }

    if (downResult.getContentLength() < 10) {
      byte[] errorContent = downResult.getErrorContent();
      if (errorContent == null) {
        LOG.error("Downloading CRL failed, CRL too short (len={}): ", downResult.getContentLength());
      } else {
        LOG.error("Downloading CRL failed with error: {}", new String(errorContent));
      }
      return;
    }

    // Extract CRLNumber from the CRL
    CrlStreamParser newCrlStreamParser = new CrlStreamParser(tmpCrlFile);
    BigInteger newCrlNumber = newCrlStreamParser.getCrlNumber();

    boolean useNewCrl = crlNumber == null || newCrlNumber.compareTo(crlNumber) > 0;
    if (useNewCrl) {
      String hashProp = hashAlgo + " " + Hex.encode(crlStream.getHashValue());
      IoUtil.save(new File(generatedDir, "new-ca.crl.fp"), hashProp.getBytes(StandardCharsets.UTF_8));
      tmpCrlFile.renameTo(new File(generatedDir, "new-ca.crl"));
      if (crlNumber == null) {
        LOG.info("Downloaded CRL at first time");
      } else {
        LOG.info("Downloaded CRL is newer than existing one");
      }
      // notify the change
      updatemeFile.createNewFile();
    } else {
      tmpCrlFile.delete();
      LOG.info("Downloaded CRL is not newer than existing one");
    }

    updateMeNowFile.delete();
  }

  static Properties loadProperties(File file) throws IOException {
    Properties props = new Properties();
    if (file.exists() && file.isFile()) {
      try (InputStream is = new FileInputStream(file)) {
        props.load(is);
      }
    }
    return props;
  }

}
