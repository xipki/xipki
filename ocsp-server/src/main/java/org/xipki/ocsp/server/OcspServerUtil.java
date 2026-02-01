// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.server.store.CaDbCertStatusStore;
import org.xipki.ocsp.server.store.CrlDbCertStatusStore;
import org.xipki.ocsp.server.store.DbCertStatusStore;
import org.xipki.ocsp.server.store.ejbca.EjbcaCertStatusStore;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.OID;
import org.xipki.security.CertPathValidationModel;
import org.xipki.security.ConcurrentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.ReflectiveUtil;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Utility functions for {@link OcspServer}.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspServerUtil {

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspServerUtil.class);

  private static final String STORE_TYPE_XIPKI_DB = "xipki-db";

  private static final String STORE_TYPE_XIPKI_CA_DB = "xipki-ca-db";

  private static final String STORE_TYPE_CRL = "crl";

  private static final String STORE_TYPE_EJBCA_DB = "ejbca-db";

  static ResponseSigner initSigner(
      OcspServerConf.Signer signerType, SecurityFactory securityFactory)
      throws InvalidConfException {
    X509Cert[] explicitCertificateChain = null;

    X509Cert explicitResponderCert = null;
    if (signerType.cert() != null) {
      explicitResponderCert = parseCert(signerType.cert());
    }

    if (explicitResponderCert != null) {
      Set<X509Cert> caCerts = null;
      if (signerType.caCerts() != null) {
        caCerts = new HashSet<>();

        for (FileOrBinary certConf : signerType.caCerts()) {
          caCerts.add(parseCert(certConf));
        }
      }

      explicitCertificateChain = X509Util.buildCertPath(
          explicitResponderCert, caCerts);
    }

    String responderSignerType = signerType.type();
    String responderKeyConf = signerType.key();

    List<String> sigAlgos = signerType.algorithms();
    if (CollectionUtil.isEmpty(sigAlgos)) {
      sigAlgos = Collections.singletonList("");
    }

    List<ConcurrentSigner> singleSigners =
        new ArrayList<>(sigAlgos.size());

    String name = signerType.name();
    List<String> succSigAlgos = new LinkedList<>();
    List<String> failSigAlgos = new LinkedList<>();

    Set<String> errorMessages = new HashSet<>();
    for (String sigAlgo : sigAlgos) {
      String signerConf = (sigAlgo.isEmpty() ? "" : "algo=" + sigAlgo + ",") +
          responderKeyConf;

      try {
        ConcurrentSigner requestorSigner =
            securityFactory.createSigner(responderSignerType,
                new SignerConf(signerConf), explicitCertificateChain);
        singleSigners.add(requestorSigner);
        succSigAlgos.add(sigAlgo);
      } catch (Exception ex) {
        failSigAlgos.add(sigAlgo);
        String errorMessage = ex.getMessage();

        boolean logExcepion = true;
        if (errorMessage != null) {
          if (errorMessages.contains(errorMessage)) {
            logExcepion = false;
          } else {
            errorMessages.add(errorMessage);
          }
        }

        if (logExcepion) {
          LogUtil.warn(LOG, ex, "error creating signer group " + name);
        }
      }
    }

    if (singleSigners.isEmpty()) {
      throw new InvalidConfException("could not create any signer group "
          + name);
    } else {
      LOG.info("Create signers of sign algorithms {} for the signer group {}",
          succSigAlgos, name);
    }

    if (!failSigAlgos.isEmpty()) {
      LOG.info("ignore sign algorithms {} for the signer group {}",
          failSigAlgos, name);
    }

    try {
      return new ResponseSigner(singleSigners);
    } catch (CertificateException | IOException ex) {
      throw new InvalidConfException(ex.getMessage(), ex);
    }
  } // method initSigner

  static OcspStore newStore(OcspServerConf.Store conf,
                            Map<String, DataSourceWrapper> datasources)
      throws InvalidConfException {
    OcspStore store;
    try {
      String type = conf.source().type();
      if (type != null) {
        type = type.trim().toLowerCase();
      }

      if (StringUtil.isBlank(type)) {
        throw new ObjectCreationException("OCSP store type is not specified");
      } else if (STORE_TYPE_XIPKI_DB.equals(type)) {
        store = new DbCertStatusStore();
      } else if (STORE_TYPE_CRL.equals(type)) {
        store = new CrlDbCertStatusStore();
      } else if (STORE_TYPE_XIPKI_CA_DB.equals(type)) {
        store = new CaDbCertStatusStore();
      } else if (STORE_TYPE_EJBCA_DB.equals(type)) {
        store = new EjbcaCertStatusStore();
      } else if (type.startsWith("java:")) {
        // "java:".length() = 5
        String className = conf.source().type().substring(5).trim();
        store = ReflectiveUtil.newInstance(className,
            OcspServerUtil.class.getClassLoader());
      } else {
        throw new ObjectCreationException("unknown OCSP store type " + type);
      }
    } catch (ObjectCreationException ex) {
      throw new InvalidConfException("ObjectCreationException of store "
          + conf.name() + ":" + ex.getMessage(), ex);
    }

    store.setName(conf.name());
    Integer interval = conf.retentionInterval();
    int retentionInterval = (interval == null) ? -1 : interval;
    store.setRetentionInterval(retentionInterval);
    store.setUnknownCertBehaviour(conf.unknownCertBehaviour());

    store.setIncludeArchiveCutoff(
        getBoolean(conf.includeArchiveCutoff(), true));
    store.setIncludeCrlId(
        getBoolean(conf.includeCrlId(), true));
    store.setIgnoreExpiredCert(
        getBoolean(conf.ignoreExpiredCert(), true));
    store.setIgnoreNotYetValidCert(
        getBoolean(conf.ignoreNotYetValidCert(), true));

    Validity minPeriod = (conf.minNextUpdatePeriod() == null)
            ? null : Validity.getInstance(conf.minNextUpdatePeriod());
    Validity maxPeriod = (conf.maxNextUpdatePeriod() == null)
            ? null : Validity.getInstance(conf.maxNextUpdatePeriod());
    store.setNextUpdatePeriodLimit(minPeriod, maxPeriod);

    if ("NEVER".equalsIgnoreCase(conf.updateInterval())) {
      store.setUpdateInterval(null);
    } else {
      String str = conf.updateInterval();
      Validity updateInterval = StringUtil.isBlank(str)
          ? new Validity(5, Validity.Unit.MINUTE)
          : Validity.getInstance(str);
      store.setUpdateInterval(updateInterval);
    }

    String datasourceName = conf.source().datasource();
    DataSourceWrapper datasource = null;
    if (datasourceName != null) {
      datasource = Optional.ofNullable(datasources.get(datasourceName))
          .orElseThrow(() -> new InvalidConfException(
              "datasource named '" + datasourceName + "' not defined"));
    }
    try {
      JsonMap sourceConf = conf.source().conf();
      store.init(sourceConf, datasource);
    } catch (OcspStoreException ex) {
      throw new InvalidConfException("CertStatusStoreException of store "
          + conf.name() + ":" + ex.getMessage(), ex);
    }

    return store;
  } // method newStore

  static boolean canBuildCertPath(
      X509Cert[] certsInReq, RequestOption requestOption,
      Instant referenceTime) {
    X509Cert target = certsInReq[0];

    Set<X509Cert> trustanchors = requestOption.trustanchors();
    Set<X509Cert> certstore = new HashSet<>(trustanchors);

    Set<X509Cert> configuredCerts = requestOption.certs();
    if (CollectionUtil.isNotEmpty(configuredCerts)) {
      certstore.addAll(requestOption.certs());
    }

    X509Cert[] certpath = X509Util.buildCertPath(target, certstore);
    CertPathValidationModel model = requestOption.certpathValidationModel();

    if (model == null || model == CertPathValidationModel.PKIX) {
      for (X509Cert m : certpath) {
        if (m.notBefore().isAfter(referenceTime)
            || m.notAfter().isBefore(referenceTime)) {
          return false;
        }
      }
    } else if (model == CertPathValidationModel.CHAIN) {
      // do nothing
    } else {
      throw new IllegalStateException("invalid CertPathValidationModel "
          + model.name());
    }

    for (int i = certpath.length - 1; i >= 0; i--) {
      X509Cert targetCert = certpath[i];
      for (X509Cert m : trustanchors) {
        if (m.equals(targetCert)) {
          return true;
        }
      }
    }

    return false;
  } // method canBuildCertPath

  private static boolean getBoolean(Boolean bo, boolean defaultValue) {
    return (bo == null) ? defaultValue : bo;
  }

  private static X509Cert parseCert(FileOrBinary certConf)
      throws InvalidConfException {
    try {
      return X509Util.parseCert(certConf.readContent());
    } catch (IOException | CertificateException ex) {
      String msg = "could not parse certificate";
      if (certConf.file() != null) {
        msg += " from file " + certConf.file();
      }
      throw new InvalidConfException(msg);
    }
  } // method parseCert

  static OcspServerConf parseConf(String confFilename)
      throws InvalidConfException {
    return OcspServerConf.readConfFromFile(
        IoUtil.expandFilepath(confFilename, true));
  }

  static ExtendedExtension removeExtension(
      List<ExtendedExtension> extensions, OID extnType) {
    ExtendedExtension extn = null;
    for (ExtendedExtension m : extensions) {
      if (extnType == m.extnType()) {
        extn = m;
        break;
      }
    }

    if (extn != null) {
      extensions.remove(extn);
    }

    return extn;
  } // method removeExtension

}
