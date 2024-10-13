// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.CertStatusInfo.UnknownCertBehaviour;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Validity;

import java.io.Closeable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Map;

/**
 * Store of certificate status.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class OcspStore implements Closeable {

  protected String name;

  protected UnknownCertBehaviour unknownCertBehaviour = UnknownCertBehaviour.unknown;

  protected boolean ignoreExpiredCert;

  protected boolean ignoreNotYetValidCert;

  protected Validity minNextUpdatePeriod;

  protected Validity maxNextUpdatePeriod;

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
  public abstract X509Cert getIssuerCert(RequestIssuer reqIssuer);

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
   * @param inheritCaRevocation
   *          Whether to inherit CA revocation
   * @return the certificate status.
   * @throws OcspStoreException
   *           If OCSP store failed to retrieve the status.
   */
  public final CertStatusInfo getCertStatus(
      Instant time, RequestIssuer reqIssuer, BigInteger serialNumber,
      boolean inheritCaRevocation)
      throws OcspStoreException {
    CertStatusInfo info =
        getCertStatus0(time, reqIssuer, serialNumber, inheritCaRevocation);

    if (info == null) {
      return null;
    }

    Instant nextUpdate = info.getNextUpdate();

    if (minNextUpdatePeriod != null) {
      Instant minNextUpdate = minNextUpdatePeriod.add(time);
      if (nextUpdate == null || minNextUpdate.isAfter(nextUpdate)) {
        info.setNextUpdate(minNextUpdate);
      }
    }

    if (maxNextUpdatePeriod != null) {
      Instant maxNextUpdate = maxNextUpdatePeriod.add(time);
      if (nextUpdate == null || nextUpdate.isAfter(maxNextUpdate)) {
        info.setNextUpdate(maxNextUpdate);
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
   * @param inheritCaRevocation
   *          Whether to inherit CA revocation
   * @return the certificate status.
   * @throws OcspStoreException
   *           If OCSP store failed to retrieve the status.
   */
  protected abstract CertStatusInfo getCertStatus0(
      Instant time, RequestIssuer reqIssuer, BigInteger serialNumber,
      boolean inheritCaRevocation)
      throws OcspStoreException;

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
  public abstract void init(Map<String, ?> sourceConf, DataSourceWrapper datasource)
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

  public void setNextUpdatePeriodLimit(Validity minNextUpdatePeriod, Validity maxNextUpdatePeriod) {
    if (minNextUpdatePeriod != null && maxNextUpdatePeriod != null) {
      if (minNextUpdatePeriod.compareTo(maxNextUpdatePeriod) > 0) {
        throw new IllegalArgumentException(
            String.format("minNextUpdatePeriod (%s) > maxNextUpdatePeriod (%s) is not allowed",
                minNextUpdatePeriod, maxNextUpdatePeriod));
      }
    }

    this.minNextUpdatePeriod = minNextUpdatePeriod;
    this.maxNextUpdatePeriod = maxNextUpdatePeriod;
  }

  public Validity getMaxNextUpdatePeriod() {
    return maxNextUpdatePeriod;
  }

  public Validity getUpdateInterval() {
    return updateInterval;
  }

  public void setUpdateInterval(Validity updateInterval) {
    this.updateInterval = updateInterval;
  }

  protected static String overviewString(X509Cert cert) {
    return "subject: " + cert.getSubjectText() + ", issuer: " + cert.getIssuerText() +
        ", serialNo: " + cert.getSerialNumberHex();
  }

}
