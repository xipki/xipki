/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
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
import org.xipki.ca.qa.certprofile.x509.X509CertProfileQA;
import org.xipki.ca.qa.certprofile.x509.X509IssuerInfo;
import org.xipki.ca.qa.certprofile.x509.jaxb.ObjectFactory;
import org.xipki.ca.qa.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.qa.shell.jaxb.FileOrValueType;
import org.xipki.ca.qa.shell.jaxb.IssuersType;
import org.xipki.ca.qa.shell.jaxb.X509IssuerType;
import org.xipki.common.ConfigurationException;
import org.xipki.common.IoUtil;
import org.xipki.common.ParamChecker;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class IssuerAndCertprofileManager
{
    private static final Logger LOG = LoggerFactory.getLogger(IssuerAndCertprofileManager.class);

    private String certProfileDir;
    private String issuerConfFile;

    private Map<String, X509CertProfileQA> x509ProfileMap = new HashMap<>();
    private Map<String, X509IssuerInfo> x509IssuerInfoMap = new HashMap<>();
    private static Unmarshaller jaxbUnmarshaller;

    public IssuerAndCertprofileManager()
    {
    }

    public void init()
    throws ConfigurationException
    {
        try
        {
            ParamChecker.assertNotNull("certProfileDir", certProfileDir);
            ParamChecker.assertNotNull("issuerConfFile", issuerConfFile);
        }catch(IllegalArgumentException e)
        {
            throw new ConfigurationException(e.getMessage());
        }

        File dir = new File(certProfileDir);
        File[] children = dir.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".xml");
            }
        });

        if(children == null || children.length < 1)
        {
            LOG.warn("Could not find any X509 certificate profile in directory {}", certProfileDir);
        } else
        {
            for(File child : children)
            {
                String filename = child.getName();
                String name = filename.substring(0, filename.length() - ".xml".length());

                try
                {
                    FileInputStream confStream = new FileInputStream(child);
                    X509ProfileType profile = X509CertProfileQA.parse(confStream);
                    x509ProfileMap.put(name, new X509CertProfileQA(profile));
                }catch(Exception e)
                {
                    throw new ConfigurationException(e.getMessage(), e);
                }
            }
        }

        IssuersType issuersConf;
        try
        {
            FileInputStream issuerConfStream = new FileInputStream(issuerConfFile);
            issuersConf = parseIssuerConf(issuerConfStream);
        }catch(IOException | JAXBException | SAXException e)
        {
            throw new ConfigurationException(e.getMessage(), e);
        }

        if(issuersConf.getX509Issuers() != null)
        {
            List<X509IssuerType> x509IssuerTypes = issuersConf.getX509Issuers().getX509Issuer();
            for(X509IssuerType issuerType : x509IssuerTypes)
            {
                byte[] certBytes;
                try
                {
                    certBytes = readData(issuerType.getCert());
                } catch (IOException e)
                {
                    throw new ConfigurationException(e.getMessage(), e);
                }
                X509IssuerInfo issuerInfo;
                try
                {
                    issuerInfo = new X509IssuerInfo(issuerType.getOcspUrl(),
                            issuerType.getCrlUrl(), issuerType.getDeltaCrlUrl(), certBytes);
                } catch (CertificateException e)
                {
                    throw new ConfigurationException(e.getMessage(), e);
                }
                x509IssuerInfoMap.put(issuerType.getName(), issuerInfo);
            }
        }

        if(x509IssuerInfoMap.isEmpty())
        {
            LOG.warn("no issuer is configured");
        }
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

    public X509CertProfileQA getCertprofile(String certprofileName)
    {
        return x509ProfileMap.get(certprofileName);
    }

    public static IssuersType parseIssuerConf(InputStream confStream)
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
                URL url = X509CertProfileQA.class.getResource("/xsd/qa-issuer.xsd");
                jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
            }

            rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(confStream);
        } finally
        {
            confStream.close();
        }

        Object rootType = rootElement.getValue();
        if(rootType instanceof IssuersType)
        {
            return (IssuersType) rootElement.getValue();
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
