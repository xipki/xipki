/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.server.store.example;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.ocsp.server.OcspServerConf;
import org.xipki.ocsp.server.store.IssuerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.util.X509Util;

import com.alibaba.fastjson.JSON;

/**
 * This is just an example that demonstrates how to use the custom OcspStore.<br/>
 * To use this store, configure the store in the <tt>ocsp-responder.json</tt> file as follows
 * <pre>
 *      "source":{
 *           "type":"java:org.xipki.ocsp.server.store.example.DummyStore",
 *           "conf":{
 *               "custom":{
 *                   "caCert":"path/to/CA-certificate-file"
 *               }
 *           }
 *       },
 * </pre>
 * Where the CA-certificate-file is either the CA certificate in DER or PEM format.<p/>
 *
 * This dummy store returns the following certificate status
 * <ul>
 * <li>GOOD if serial-number % 3 == 0</li>
 * <li>REVOKED if serial-number % 3 == 1</li>
 * <li>UNKNOWN if serial-number % 3 == 2</li>
 * </ul>
 * @author Lijun Liao
 * @since 5.0.2
 */
public class DummyStore extends OcspStore {

  public static class DummySourceConf {

    private String caCert;

    public String getCaCert() {
      return caCert;
    }

    public void setCaCert(String caCert) {
      this.caCert = caCert;
    }

  }

  private static Logger LOG = LoggerFactory.getLogger(DummyStore.class);

  private static final BigInteger BN_3 = BigInteger.valueOf(3);

  private IssuerEntry issuserEntry;

  private X509Certificate issuerCert;

  public DummyStore() {
    LOG.error("This DummyStore is only for demo, do NOT use it production environment");
  }

  @Override
  public void close() throws IOException {
  }

  @Override
  public boolean knowsIssuer(RequestIssuer reqIssuer) {
      return issuserEntry.matchHash(reqIssuer);
  }

  @Override
  public X509Certificate getIssuerCert(RequestIssuer reqIssuer) {
      return issuserEntry.matchHash(reqIssuer) ? issuerCert : null;
  }

  @Override
  protected CertStatusInfo getCertStatus0(Date time, RequestIssuer reqIssuer,
      BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
      boolean inheritCaRevocation) throws OcspStoreException {
    if (!knowsIssuer(reqIssuer)) {
      return null;
    }

    final int rest = serialNumber.mod(BN_3).intValue();
    Date thisUpdate = new Date();
    Date nextUpdate = new Date(thisUpdate.getTime() + 12 * 60 * 60 * 1000L); // 12 hours

    if (rest == 0) {
        return CertStatusInfo.getGoodCertStatusInfo(new Date(), nextUpdate);
    } else if (rest == 1) {
        CertRevocationInfo revInfo = new CertRevocationInfo(CrlReason.KEY_COMPROMISE);
        return CertStatusInfo.getRevokedCertStatusInfo(revInfo, thisUpdate, nextUpdate);
    } else {
        return CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
    }
  }

  @Override
  public void init(SourceConf sourceConf, DataSourceWrapper datasource) throws OcspStoreException {
    if (sourceConf != null && !(sourceConf instanceof OcspServerConf.SourceConfImpl)) {
      throw new OcspStoreException("unknown conf " + sourceConf.getClass().getName());
    }

    Object custom = ((OcspServerConf.SourceConfImpl)  sourceConf).getCustom();
    if (custom == null) {
      throw new OcspStoreException("Source.custom not specified");
    }

    DummySourceConf conf = JSON.parseObject(JSON.toJSONBytes(custom), DummySourceConf.class);
    String cacertFile = conf.getCaCert();
    X509Certificate cert;
    IssuerEntry issuserEntry;
    try {
      cert = X509Util.parseCert(new File(cacertFile));
      issuserEntry = new IssuerEntry(1, cert);
    } catch (CertificateException | IOException ex) {
      throw new OcspStoreException("cannot parse the cacert " + cacertFile, ex);
    }

    this.issuerCert = cert;
    this.issuserEntry = issuserEntry;
    LOG.info("use caCert {}", cacertFile);
  }

  @Override
  public boolean isHealthy() {
      return true;
  }

}
