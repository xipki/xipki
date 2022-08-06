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

package org.xipki.ocsp.server;

import com.alibaba.fastjson.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspServer;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.server.store.CaDbCertStatusStore;
import org.xipki.ocsp.server.store.CrlDbCertStatusStore;
import org.xipki.ocsp.server.store.DbCertStatusStore;
import org.xipki.ocsp.server.store.ejbca.EjbcaCertStatusStore;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.OID;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * Implementation of {@link OcspServer}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspServerUtil {

  private static final Logger LOG = LoggerFactory.getLogger(OcspServerUtil.class);

  private static final String STORE_TYPE_XIPKI_DB = "xipki-db";

  private static final String STORE_TYPE_XIPKI_CA_DB = "xipki-ca-db";

  private static final String STORE_TYPE_CRL = "crl";

  private static final String STORE_TYPE_EJBCA_DB = "ejbca-db";

  static ResponseSigner initSigner(
      OcspServerConf.Signer signerType, SecurityFactory securityFactory)
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
        throw new InvalidConfException(ex);
      }
    }

    String responderSignerType = signerType.getType();
    String responderKeyConf = signerType.getKey();

    List<String> sigAlgos = signerType.getAlgorithms();
    List<ConcurrentContentSigner> singleSigners = new ArrayList<>(sigAlgos.size());

    String name = signerType.getName();
    List<String> succSigAlgos = new LinkedList<>();
    List<String> failSigAlgos = new LinkedList<>();
    for (String sigAlgo : sigAlgos) {
      try {
        ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
            responderSignerType, new SignerConf("algo=" + sigAlgo + "," + responderKeyConf),
            explicitCertificateChain);
        singleSigners.add(requestorSigner);
        succSigAlgos.add(sigAlgo);
      } catch (Exception ex) {
        failSigAlgos.add(sigAlgo);
        LOG.debug("could not create OCSP responder " + name, ex);
        //throw new InvalidConfException(ex.getMessage(), ex);
      }
    }

    if (singleSigners.isEmpty()) {
      throw new InvalidConfException("could not create any signer for OCSP responder " + name);
    } else {
      LOG.info("Create signers of sign algorithms {} for the OCSP responder {}",
          succSigAlgos, name);
    }

    if (!failSigAlgos.isEmpty()) {
      LOG.info("ignore sign algorithms {} for the OCSP responder {}", failSigAlgos, name);
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
      } else if (STORE_TYPE_EJBCA_DB.equals(type)) {
        store = new EjbcaCertStatusStore();
      } else if (type.startsWith("java:")) {
        String className = type.substring("java:".length()).trim();
        try {
          Class<?> clazz = Class.forName(className, false, OcspServerUtil.class.getClassLoader());
          store = (OcspStore) clazz.newInstance();
        } catch (ClassNotFoundException | ClassCastException | InstantiationException
                | IllegalAccessException ex) {
          throw new InvalidConfException("ObjectCreationException of store " + conf.getName()
              + ":" + ex.getMessage(), ex);
        }
      } else {
        throw new ObjectCreationException("unknown OCSP store type " + type);
      }
    } catch (ObjectCreationException ex) {
      throw new InvalidConfException("ObjectCreationException of store " + conf.getName()
          + ":" + ex.getMessage(), ex);
    }

    store.setName(conf.getName());
    Integer interval = conf.getRetentionInterval();
    int retentionInterva = (interval == null) ? -1 : interval;
    store.setRetentionInterval(retentionInterva);
    store.setUnknownCertBehaviour(conf.getUnknownCertBehaviour());

    store.setIncludeArchiveCutoff(getBoolean(conf.getIncludeArchiveCutoff(), true));
    store.setIncludeCrlId(getBoolean(conf.getIncludeCrlId(), true));

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
      datasource = datasources.get(datasourceName);
      if (datasource == null) {
        throw new InvalidConfException("datasource named '" + datasourceName + "' not defined");
      }
    }
    try {
      Map<String, ?> sourceConf = conf.getSource().getConf();
      store.init(sourceConf, datasource);
    } catch (OcspStoreException ex) {
      throw new InvalidConfException("CertStatusStoreException of store " + conf.getName()
          + ":" + ex.getMessage(), ex);
    }

    return store;
  } // method newStore

  static boolean canBuildCertpath(X509Cert[] certsInReq,
      RequestOption requestOption, Date referenceTime) {
    X509Cert target = certsInReq[0];

    Set<X509Cert> trustanchors = requestOption.getTrustanchors();
    Set<X509Cert> certstore = new HashSet<>(trustanchors);

    Set<X509Cert> configuredCerts = requestOption.getCerts();
    if (CollectionUtil.isNotEmpty(configuredCerts)) {
      certstore.addAll(requestOption.getCerts());
    }

    X509Cert[] certpath;
    try {
      certpath = X509Util.buildCertPath(target, certstore);
    } catch (CertPathBuilderException ex) {
      LogUtil.warn(LOG, ex);
      return false;
    }

    CertpathValidationModel model = requestOption.getCertpathValidationModel();

    if (model == null || model == CertpathValidationModel.PKIX) {
      for (X509Cert m : certpath) {
        if (m.getNotBefore().after(referenceTime)
                || m.getNotAfter().before(referenceTime)) {
          return false;
        }
      }
    } else if (model == CertpathValidationModel.CHAIN) {
      // do nothing
    } else {
      throw new IllegalStateException("invalid CertpathValidationModel " + model.name());
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
  } // method canBuildCertpath

  private static boolean getBoolean(Boolean bo, boolean defaultValue) {
    return (bo == null) ? defaultValue : bo;
  }

  private static InputStream getInputStream(FileOrBinary conf)
      throws IOException {
    return (conf.getFile() != null)
        ? Files.newInputStream(Paths.get(IoUtil.expandFilepath(conf.getFile(), true)))
        : new ByteArrayInputStream(conf.getBinary());
  }

  static InputStream getInputStream(FileOrValue conf)
      throws IOException {
    return (conf.getFile() != null)
        ? Files.newInputStream(Paths.get(IoUtil.expandFilepath(conf.getFile(), true)))
        : new ByteArrayInputStream(StringUtil.toUtf8Bytes(conf.getValue()));
  }

  static void closeStream(InputStream stream) {
    if (stream == null) {
      return;
    }

    try {
      stream.close();
    } catch (IOException ex) {
      LOG.warn("could not close stream: {}", ex.getMessage());
    }
  }

  private static X509Cert parseCert(FileOrBinary certConf)
      throws InvalidConfException {
    InputStream is = null;
    try {
      is = getInputStream(certConf);
      return X509Util.parseCert(is);
    } catch (IOException | CertificateException ex) {
      String msg = "could not parse certificate";
      if (certConf.getFile() != null) {
        msg += " from file " + certConf.getFile();
      }
      throw new InvalidConfException(msg);
    } finally {
      closeStream(is);
    }
  } // method parseCert

  static OcspServerConf parseConf(String confFilename)
      throws InvalidConfException {
    try (InputStream is = Files.newInputStream(
          Paths.get(IoUtil.expandFilepath(confFilename, true)))) {
      OcspServerConf root = JSON.parseObject(is, OcspServerConf.class);
      root.validate();
      return root;
    } catch (IOException | RuntimeException ex) {
      throw new InvalidConfException("parse profile failed, message: " + ex.getMessage(), ex);
    }
  } // method parseConf

  static ExtendedExtension removeExtension(List<ExtendedExtension> extensions,
      OID extnType) {
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
