/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.qa.shell;

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
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.qa.X509CertprofileQA;
import org.xipki.ca.qa.X509IssuerInfo;
import org.xipki.ca.qa.shell.internal.jaxb.FileOrValueType;
import org.xipki.ca.qa.shell.internal.jaxb.ObjectFactory;
import org.xipki.ca.qa.shell.internal.jaxb.QAConfType;
import org.xipki.ca.qa.shell.internal.jaxb.X509CertprofileType;
import org.xipki.ca.qa.shell.internal.jaxb.X509IssuerType;
import org.xipki.common.IoUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.XMLUtil;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class QASystemManager
{
    private static final Logger LOG = LoggerFactory.getLogger(QASystemManager.class);

    private String confFile;

    public String getConfFile()
    {
        return confFile;
    }

    public void setConfFile(String confFile)
    {
        this.confFile = confFile;
    }

    private Map<String, X509CertprofileQA> x509ProfileMap = new HashMap<>();
    private Map<String, X509IssuerInfo> x509IssuerInfoMap = new HashMap<>();
    private static Unmarshaller jaxbUnmarshaller;

    public QASystemManager()
    {
    }

    public void init()
    {
        if(XipkiOsgiCommandSupport.isBlank(confFile))
        {
            LOG.error("confFile could not be null and empty");
            return;
        }

        QAConfType qaConf;
        try
        {
            FileInputStream issuerConfStream = new FileInputStream(confFile);
            qaConf = parseQAConf(issuerConfStream);
        }catch(IOException | JAXBException | SAXException e)
        {
            final String message = "Could not parse the QA configuration";
            String exceptionMessage;
            if(e instanceof JAXBException)
            {
                exceptionMessage = XMLUtil.getMessage((JAXBException) e);
            } else
            {
                exceptionMessage = e.getMessage();
            }
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), exceptionMessage);
            }
            LOG.debug(message, e);
            return;
        }

        if(qaConf.getX509Issuers() != null)
        {
            List<X509IssuerType> x509IssuerTypes = qaConf.getX509Issuers().getX509Issuer();
            for(X509IssuerType issuerType : x509IssuerTypes)
            {
                byte[] certBytes;
                try
                {
                    certBytes = readData(issuerType.getCert());
                } catch (IOException e)
                {
                    final String message = "Could not read the certificate bytes of issuer " + issuerType.getName();
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                    continue;
                }
                X509IssuerInfo issuerInfo;
                try
                {
                    issuerInfo = new X509IssuerInfo(issuerType.getOcspUrl(),
                            issuerType.getCrlUrl(), issuerType.getDeltaCrlUrl(), certBytes);
                } catch (CertificateException e)
                {
                    final String message = "Could not parse certificate of issuer " + issuerType.getName();
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                    continue;
                }
                x509IssuerInfoMap.put(issuerType.getName(), issuerInfo);
                LOG.info("configured X509 issuer {}", issuerType.getName());
            }
        }

        if(qaConf.getX509Certprofiles() != null)
        {
            List<X509CertprofileType> certprofileTypes = qaConf.getX509Certprofiles().getX509Certprofile();
            for(X509CertprofileType type : certprofileTypes)
            {
                String name = type.getName();
                try
                {
                    byte[] content = readData(type);
                    x509ProfileMap.put(name, new X509CertprofileQA(content));
                    LOG.info("configured X509 certificate profile {}", name);
                }catch(IOException | CertprofileException e)
                {
                    final String message = "Could not parse QA certificate profile " + name;
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                    continue;
                }
            }
        }
    }

    public void shutdown()
    {
    }

    public Set<String> getIssuerNames()
    {
        return Collections.unmodifiableSet(x509IssuerInfoMap.keySet());
    }

    public X509IssuerInfo getIssuer(String issuerName)
    {
        return x509IssuerInfoMap.get(issuerName);
    }

    public Set<String> getCertprofileNames()
    {
        return Collections.unmodifiableSet(x509ProfileMap.keySet());
    }

    public X509CertprofileQA getCertprofile(String certprofileName)
    {
        return x509ProfileMap.get(certprofileName);
    }

    public static QAConfType parseQAConf(InputStream confStream)
    throws IOException, JAXBException, SAXException
    {
        JAXBElement<?> rootElement;
        try
        {
            if(jaxbUnmarshaller == null)
            {
                JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                jaxbUnmarshaller = context.createUnmarshaller();

                final SchemaFactory schemaFact = SchemaFactory.newInstance(
                        javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                URL url = QASystemManager.class.getResource("/xsd/qa-conf.xsd");
                jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
            }

            rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(confStream);
        } finally
        {
            confStream.close();
        }

        Object rootType = rootElement.getValue();
        if(rootType instanceof QAConfType)
        {
            return (QAConfType) rootElement.getValue();
        }
        else
        {
            throw new SAXException("invalid root element type");
        }
    }

    private static byte[] readData(FileOrValueType fileOrValue)
    throws IOException
    {
        byte[] data = fileOrValue.getValue();
        if(data == null)
        {
            data = IoUtil.read(fileOrValue.getFile());
        }
        return data;
    }
}
