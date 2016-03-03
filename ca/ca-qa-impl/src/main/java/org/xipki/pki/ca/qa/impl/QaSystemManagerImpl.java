/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.qa.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.common.util.XmlUtil;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.qa.api.QaSystemManager;
import org.xipki.pki.ca.qa.api.X509CertprofileQa;
import org.xipki.pki.ca.qa.api.X509IssuerInfo;
import org.xipki.pki.ca.qa.impl.jaxb.FileOrValueType;
import org.xipki.pki.ca.qa.impl.jaxb.ObjectFactory;
import org.xipki.pki.ca.qa.impl.jaxb.QAConfType;
import org.xipki.pki.ca.qa.impl.jaxb.X509CertprofileType;
import org.xipki.pki.ca.qa.impl.jaxb.X509IssuerType;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaSystemManagerImpl implements QaSystemManager {

    private static final Logger LOG = LoggerFactory.getLogger(QaSystemManagerImpl.class);

    private static Unmarshaller jaxbUnmarshaller;

    private String confFile;

    private Map<String, X509CertprofileQaImpl> x509ProfileMap = new HashMap<>();

    private Map<String, X509IssuerInfo> x509IssuerInfoMap = new HashMap<>();

    public QaSystemManagerImpl() {
    }

    public String getConfFile() {
        return confFile;
    }

    public void setConfFile(
            final String confFile) {
        this.confFile = confFile;
    }

    public void init() {
        if (StringUtil.isBlank(confFile)) {
            LOG.error("confFile must not be null and empty");
            return;
        }

        QAConfType qaConf;
        try {
            FileInputStream issuerConfStream = new FileInputStream(confFile);
            qaConf = parseQaConf(issuerConfStream);
        } catch (IOException | JAXBException | SAXException ex) {
            final String message = "could not parse the QA configuration";
            String exceptionMessage;
            if (ex instanceof JAXBException) {
                exceptionMessage = XmlUtil.getMessage((JAXBException) ex);
            } else {
                exceptionMessage = ex.getMessage();
            }
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        exceptionMessage);
            }
            LOG.debug(message, ex);
            return;
        }

        if (qaConf.getX509Issuers() != null) {
            List<X509IssuerType> x509IssuerTypes = qaConf.getX509Issuers().getX509Issuer();
            for (X509IssuerType issuerType : x509IssuerTypes) {
                byte[] certBytes;
                try {
                    certBytes = readData(issuerType.getCert());
                } catch (IOException ex) {
                    final String message = "could not read the certificate bytes of issuer "
                            + issuerType.getName();
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                                ex.getMessage());
                    }
                    LOG.debug(message, ex);
                    continue;
                }

                X509IssuerInfo issuerInfo;
                try {
                    issuerInfo = new X509IssuerInfo(issuerType.getCaIssuerUrl(),
                            issuerType.getOcspUrl(),
                            issuerType.getCrlUrl(),
                            issuerType.getDeltaCrlUrl(), certBytes);
                } catch (CertificateException ex) {
                    final String message =
                            "could not parse certificate of issuer " + issuerType.getName();
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message),
                                ex.getClass().getName(), ex.getMessage());
                    }
                    LOG.debug(message, ex);
                    continue;
                }

                x509IssuerInfoMap.put(issuerType.getName(), issuerInfo);
                LOG.info("configured X509 issuer {}", issuerType.getName());
            }
        }

        if (qaConf.getX509Certprofiles() != null) {
            List<X509CertprofileType> certprofileTypes =
                    qaConf.getX509Certprofiles().getX509Certprofile();
            for (X509CertprofileType type : certprofileTypes) {
                String name = type.getName();
                try {
                    byte[] content = readData(type);
                    x509ProfileMap.put(name, new X509CertprofileQaImpl(content));
                    LOG.info("configured X509 certificate profile {}", name);
                } catch (IOException | CertprofileException ex) {
                    final String message = "could not parse QA certificate profile " + name;
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message),
                                ex.getClass().getName(), ex.getMessage());
                    }
                    LOG.debug(message, ex);
                    continue;
                }
            }
        }
    } // method init

    public void shutdown() {
    }

    @Override
    public Set<String> getIssuerNames() {
        return Collections.unmodifiableSet(x509IssuerInfoMap.keySet());
    }

    @Override
    public X509IssuerInfo getIssuer(
            final String issuerName) {
        return x509IssuerInfoMap.get(issuerName);
    }

    @Override
    public Set<String> getCertprofileNames() {
        return Collections.unmodifiableSet(x509ProfileMap.keySet());
    }

    @Override
    public X509CertprofileQa getCertprofile(
            final String certprofileName) {
        return x509ProfileMap.get(certprofileName);
    }

    private static QAConfType parseQaConf(
            final InputStream confStream)
    throws IOException, JAXBException, SAXException {
        JAXBElement<?> rootElement;
        try {
            if (jaxbUnmarshaller == null) {
                JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                jaxbUnmarshaller = context.createUnmarshaller();

                final SchemaFactory schemaFact = SchemaFactory.newInstance(
                        javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                URL url = QaSystemManagerImpl.class.getResource("/xsd/caqa-conf.xsd");
                jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
            }

            rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(confStream);
        } finally {
            confStream.close();
        }

        Object rootType = rootElement.getValue();
        if (rootType instanceof QAConfType) {
            return (QAConfType) rootElement.getValue();
        } else {
            throw new SAXException("invalid root element type");
        }
    }

    private static byte[] readData(
            final FileOrValueType fileOrValue)
    throws IOException {
        byte[] data = fileOrValue.getValue();
        if (data == null) {
            data = IoUtil.read(fileOrValue.getFile());
        }
        return data;
    }

}
