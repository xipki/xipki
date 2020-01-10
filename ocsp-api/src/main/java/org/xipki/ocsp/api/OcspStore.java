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

package org.xipki.ocsp.api;

import java.io.Closeable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.CertStatusInfo.UnknownCertBehaviour;
import org.xipki.util.Args;
import org.xipki.util.Validity;

/**
 * Store of certificate status.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class OcspStore implements Closeable {

  protected static final long DAY = 24L * 60 * 60 * 1000;

  protected String name;

  protected UnknownCertBehaviour unknownCertBehaviour = UnknownCertBehaviour.unknown;

  protected int retentionInterval;

  protected boolean includeArchiveCutoff;

  protected boolean includeCrlId;

  protected boolean ignoreExpiredCert;

  protected boolean ignoreNotYetValidCert;

  protected Validity minNextUpdatePeriod;

  protected Validity updateInterval;

  public OcspStore() {
  }

  /**
   * Whether the store knows the reqIssuer.
   * @param reqIssuer
   *          Requested issuer
   * @return whether this OCSP store knows the given issuer.
   */
  public abstract boolean knowsIssuer(RequestIssuer reqIssuer);

  /**
   * Returns the certificate for the given {@link RequestIssuer}.
   *
   * @param reqIssuer
   *          Requested issuer
   * @return the certificate of the given issuer.
   */
  public abstract X509Certificate getIssuerCert(RequestIssuer reqIssuer);

  /**
   * Ignores expired CRLs. Only applied to CRL-based datasource.
   *
   * @return whether expired CRLs will be ignored.
   */
  protected boolean isIgnoreExpiredCrls() {
    return false;
  }

  /**
   * Return the certificate status.
   *
   * @param time
   *          Time of the certificate status. Must not be {@code null}.
   * @param reqIssuer
   *          Requested issuer
   * @param serialNumber
   *          Serial number of the target certificate. Must not be {@code null}.
   * @param includeCertHash
   *          Whether to include the hash of target certificate in the response.
   * @param includeRit
   *          Whether to include the revocation invalidity time in the response.
   * @param inheritCaRevocation
   *          Whether to inherit CA revocation
   * @return the certificate status.
   * @throws OcspStoreException
   *           If OCSP store failed to retrieve the status.
   */
  public final CertStatusInfo getCertStatus(Date time, RequestIssuer reqIssuer,
      BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
      boolean inheritCaRevocation) throws OcspStoreException {
    CertStatusInfo info = getCertStatus0(time, reqIssuer, serialNumber,
        includeCertHash, includeRit, inheritCaRevocation);

    if (info != null && minNextUpdatePeriod != null && !isIgnoreExpiredCrls()) {
      if (unknownCertBehaviour == UnknownCertBehaviour.good
          || unknownCertBehaviour == UnknownCertBehaviour.unknown) {
        Date nextUpdate = info.getNextUpdate();
        Date minNextUpdate = minNextUpdatePeriod.add(time);

        if (nextUpdate != null) {
          if (minNextUpdate.after(nextUpdate)) {
            info.setNextUpdate(minNextUpdate);
          }
        } else {
          info.setNextUpdate(minNextUpdate);
        }
      }
    }

    return info;
  } // method getCertStatus

  /**
   * Return the certificate status.
   *
   * @param time
   *          Time of the certificate status. Must not be {@code null}.
   * @param reqIssuer
   *          Requested issuer
   * @param serialNumber
   *          Serial number of the target certificate. Must not be {@code null}.
   * @param includeCertHash
   *          Whether to include the hash of target certificate in the response.
   * @param includeRit
   *          Whether to include the revocation invalidity time in the response.
   * @param inheritCaRevocation
   *          Whether to inherit CA revocation
   * @return the certificate status.
   * @throws OcspStoreException
   *           If OCSP store failed to retrieve the status.
   */
  protected abstract CertStatusInfo getCertStatus0(Date time, RequestIssuer reqIssuer,
      BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
      boolean inheritCaRevocation) throws OcspStoreException;

  /**
   * Initialize the OCSP store.
   *
   * @param sourceConf
   *          Source configuration. Could be {@code null}.
   * @param datasource
   *          Datasource. Could be {@code null}.
   * @throws OcspStoreException
   *           If OCSP store cannot be initialized.
   */
  public abstract void init(Map<String, ? extends Object> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException;

  public abstract boolean isHealthy();

  public void setName(String name) {
    this.name = Args.notBlank(name, "name");
  }

  public String getName() {
    return name;
  }

  public UnknownCertBehaviour getUnknownCertBehaviour() {
    return unknownCertBehaviour;
  }

  public void setUnknownCertBehaviour(UnknownCertBehaviour unknownCertBehaviour) {
    this.unknownCertBehaviour = unknownCertBehaviour;
  }

  public boolean isIncludeArchiveCutoff() {
    return includeArchiveCutoff;
  }

  public void setIncludeArchiveCutoff(boolean includeArchiveCutoff) {
    this.includeArchiveCutoff = includeArchiveCutoff;
  }

  public int getRetentionInterval() {
    return retentionInterval;
  }

  public void setRetentionInterval(int retentionInterval) {
    this.retentionInterval = retentionInterval;
  }

  public boolean isIncludeCrlId() {
    return includeCrlId;
  }

  public void setIncludeCrlId(boolean includeCrlId) {
    this.includeCrlId = includeCrlId;
  }

  public boolean isIgnoreExpiredCert() {
    return ignoreExpiredCert;
  }

  public void setIgnoreExpiredCert(boolean ignoreExpiredCert) {
    this.ignoreExpiredCert = ignoreExpiredCert;
  }

  public boolean isIgnoreNotYetValidCert() {
    return ignoreNotYetValidCert;
  }

  public void setIgnoreNotYetValidCert(boolean ignoreNotYetValidCert) {
    this.ignoreNotYetValidCert = ignoreNotYetValidCert;
  }

  public Validity getMinNextUpdatePeriod() {
    return minNextUpdatePeriod;
  }

  public void setMinNextUpdatePeriod(Validity minNextUpdatePeriod) {
    this.minNextUpdatePeriod = minNextUpdatePeriod;
  }

  public Validity getUpdateInterval() {
    return updateInterval;
  }

  public void setUpdateInterval(Validity updateInterval) {
    this.updateInterval = updateInterval;
  }

}
