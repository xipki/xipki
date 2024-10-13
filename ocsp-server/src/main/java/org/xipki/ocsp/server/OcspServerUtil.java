// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.server.store.CaDbCertStatusStore;
import org.xipki.ocsp.server.store.CrlDbCertStatusStore;
import org.xipki.ocsp.server.store.DbCertStatusStore;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.OID;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.FileOrBinary;
import org.xipki.util.IoUtil;
import org.xipki.util.JSON;
import org.xipki.util.LogUtil;
import org.xipki.util.ReflectiveUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
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
 * @since 2.0.0
 */

public class OcspServerUtil {

  private static final Logger LOG = LoggerFactory.getLogger(OcspServerUtil.class);

  private static final String STORE_TYPE_XIPKI_DB = "xipki-db";

  private static final String STORE_TYPE_XIPKI_CA_DB = "xipki-ca-db";

  private static final String STORE_TYPE_CRL = "crl";

  static ResponseSigner initSigner(OcspServerConf.Signer signerType, SecurityFactory securityFactory)
      throws InvalidConfException {
    X509Cert[] explicitCertificateChain = null;

    X509Cert explicitResponderCert = null;
    if (signerType.getCert() != null) {
      explicitResponderCert = parseCert(signerType.getCert());
    }

    if (explicitResponderCert != null) {
      Set<X509Cert> caCerts = null;
      if (signerType.getCaCerts() != null) {
        caCerts = new HashSet<>();

        for (FileOrBinary certConf : signerType.getCaCerts()) {
          caCerts.add(parseCert(certConf));
        }
      }

      try {
        explicitCertificateChain = X509Util.buildCertPath(explicitResponderCert, caCerts);
      } catch (CertPathBuilderException ex) {
        throw new InvalidConfException(ex.getMessage(), ex);
      }
    }

    String responderSignerType = signerType.getType();
    String responderKeyConf = signerType.getKey();

    List<String> sigAlgos = signerType.getAlgorithms();
    List<ConcurrentContentSigner> singleSigners = new ArrayList<>(sigAlgos.size());

    String name = signerType.getName();
    List<String> succSigAlgos = new LinkedList<>();
    List<String> failSigAlgos = new LinkedList<>();

    Set<String> errorMessages = new HashSet<>();
    for (String sigAlgo : sigAlgos) {
      try {
        ConcurrentContentSigner requestorSigner = securityFactory.createSigner(responderSignerType,
            new SignerConf("algo=" + sigAlgo + "," + responderKeyConf), explicitCertificateChain);
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
      throw new InvalidConfException("could not create any signer group " + name);
    } else {
      LOG.info("Create signers of sign algorithms {} for the signer group {}", succSigAlgos, name);
    }

    if (!failSigAlgos.isEmpty()) {
      LOG.info("ignore sign algorithms {} for the signer group {}", failSigAlgos, name);
    }

    try {
      return new ResponseSigner(singleSigners);
    } catch (CertificateException | IOException ex) {
      throw new InvalidConfException(ex.getMessage(), ex);
    }
  } // method initSigner

  static OcspStore newStore(OcspServerConf.Store conf, Map<String, DataSourceWrapper> datasources)
      throws InvalidConfException {
    OcspStore store;
    try {
      String type = conf.getSource().getType();
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
      } else if (type.startsWith("java:")) {
        String className = conf.getSource().getType().substring("java:".length()).trim();
        store = ReflectiveUtil.newInstance(className, OcspServerUtil.class.getClassLoader());
      } else {
        throw new ObjectCreationException("unknown OCSP store type " + type);
      }
    } catch (ObjectCreationException ex) {
      throw new InvalidConfException("ObjectCreationException of store " + conf.getName() + ":" + ex.getMessage(), ex);
    }

    store.setName(conf.getName());
    store.setUnknownCertBehaviour(conf.getUnknownCertBehaviour());

    store.setIgnoreExpiredCert(getBoolean(conf.getIgnoreExpiredCert(), true));
    store.setIgnoreNotYetValidCert(getBoolean(conf.getIgnoreNotYetValidCert(), true));

    Validity minPeriod = conf.getMinNextUpdatePeriod() == null
            ? null : Validity.getInstance(conf.getMinNextUpdatePeriod());
    Validity maxPeriod = conf.getMaxNextUpdatePeriod() == null
            ? null : Validity.getInstance(conf.getMaxNextUpdatePeriod());
    store.setNextUpdatePeriodLimit(minPeriod, maxPeriod);

    if ("NEVER".equalsIgnoreCase(conf.getUpdateInterval())) {
      store.setUpdateInterval(null);
    } else {
      String str = conf.getUpdateInterval();
      Validity updateInterval = Validity.getInstance(StringUtil.isBlank(str) ? "5m" : str);
      store.setUpdateInterval(updateInterval);
    }

    String datasourceName = conf.getSource().getDatasource();
    DataSourceWrapper datasource = null;
    if (datasourceName != null) {
      datasource = Optional.ofNullable(datasources.get(datasourceName)).orElseThrow(() ->
        new InvalidConfException("datasource named '" + datasourceName + "' not defined"));
    }
    try {
      Map<String, ?> sourceConf = conf.getSource().getConf();
      store.init(sourceConf, datasource);
    } catch (OcspStoreException ex) {
      throw new InvalidConfException("CertStatusStoreException of store " + conf.getName() + ":" + ex.getMessage(), ex);
    }

    return store;
  } // method newStore

  private static boolean getBoolean(Boolean bo, boolean defaultValue) {
    return (bo == null) ? defaultValue : bo;
  }

  private static X509Cert parseCert(FileOrBinary certConf) throws InvalidConfException {
    try {
      return X509Util.parseCert(certConf.readContent());
    } catch (IOException | CertificateException ex) {
      String msg = "could not parse certificate";
      if (certConf.getFile() != null) {
        msg += " from file " + certConf.getFile();
      }
      throw new InvalidConfException(msg);
    }
  } // method parseCert

  static OcspServerConf parseConf(String confFilename) throws InvalidConfException {
    try {
      OcspServerConf root = JSON.parseConf(
          Paths.get(IoUtil.expandFilepath(confFilename, true)), OcspServerConf.class);
      root.validate();
      return root;
    } catch (IOException | RuntimeException ex) {
      throw new InvalidConfException("parse profile failed, message: " + ex.getMessage(), ex);
    }
  } // method parseConf

  static ExtendedExtension removeExtension(List<ExtendedExtension> extensions, OID extnType) {
    ExtendedExtension extn = null;
    for (ExtendedExtension m : extensions) {
      if (extnType == m.getExtnType()) {
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
