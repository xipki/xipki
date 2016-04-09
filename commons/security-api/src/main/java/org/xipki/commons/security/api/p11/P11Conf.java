/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.commons.security.api.p11;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.internal.p11.jaxb.ModuleType;
import org.xipki.commons.security.api.internal.p11.jaxb.ModulesType;
import org.xipki.commons.security.api.internal.p11.jaxb.ObjectFactory;
import org.xipki.commons.security.api.internal.p11.jaxb.PKCS11ConfType;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11Conf {

    private static final Logger LOG = LoggerFactory.getLogger(P11Conf.class);

    private final Map<String, P11ModuleConf> moduleConfs;

    private final Set<String> moduleNames;

    public P11Conf(
            final InputStream confStream,
            final SecurityFactory securityFactory)
    throws InvalidConfException, IOException {
        ParamUtil.requireNonNull("confStream", confStream);
        ParamUtil.requireNonNull("securityFactory", securityFactory);

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            SchemaFactory schemaFact = SchemaFactory.newInstance(
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFact.newSchema(getClass().getResource(
                    "/xsd/pkcs11-conf.xsd"));
            unmarshaller.setSchema(schema);
            @SuppressWarnings("unchecked")
            JAXBElement<PKCS11ConfType> rootElement = (JAXBElement<PKCS11ConfType>)
                    unmarshaller.unmarshal(confStream);
            PKCS11ConfType pkcs11Conf = rootElement.getValue();
            ModulesType modulesType = pkcs11Conf.getModules();

            Map<String, P11ModuleConf> confs = new HashMap<>();
            for (ModuleType moduleType : modulesType.getModule()) {
                P11ModuleConf conf = new P11ModuleConf(moduleType, securityFactory);
                confs.put(conf.getName(), conf);
            } // end for (ModuleType moduleType

            if (!confs.containsKey(P11CryptServiceFactory.DEFAULT_P11MODULE_NAME)) {
                throw new InvalidConfException("module '"
                        + P11CryptServiceFactory.DEFAULT_P11MODULE_NAME + "' is not defined");
            }
            this.moduleConfs = Collections.unmodifiableMap(confs);
            this.moduleNames = Collections.unmodifiableSet(new HashSet<>(confs.keySet()));
        } catch (JAXBException | SAXException ex) {
            final String message = "invalid PKCS#11 configuration" ;
            final String exeptionMsg;
            if (ex instanceof JAXBException) {
                exeptionMsg = getMessage((JAXBException) ex);
            } else {
                exeptionMsg = ex.getMessage();
            }
            LOG.error(LogUtil.getErrorLog(exeptionMsg), ex.getClass().getName(), ex.getMessage());
            LOG.debug(message, ex);

            throw new InvalidConfException(message);
        } finally {
            confStream.close();
        }
    }

    public Set<String> getModuleNames() {
        return moduleNames;
    }

    public P11ModuleConf getModuleConf(
            final String moduleName) {
        return moduleConfs.get(moduleName);
    }

    private static String getMessage(
            final JAXBException ex) {
        String ret = ex.getMessage();
        if (ret == null && ex.getLinkedException() != null) {
            ret = ex.getLinkedException().getMessage();
        }
        return ret;
    }

}
