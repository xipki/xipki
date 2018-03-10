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

package org.xipki.security.pkcs11;

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
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.password.PasswordResolver;
import org.xipki.security.pkcs11.jaxb.MechnanismSetsType;
import org.xipki.security.pkcs11.jaxb.ModuleType;
import org.xipki.security.pkcs11.jaxb.ModulesType;
import org.xipki.security.pkcs11.jaxb.ObjectFactory;
import org.xipki.security.pkcs11.jaxb.PKCS11ConfType;
import org.xml.sax.SAXException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11Conf {

  private static final Logger LOG = LoggerFactory.getLogger(P11Conf.class);

  private final Map<String, P11ModuleConf> moduleConfs;

  private final Set<String> moduleNames;

  public P11Conf(InputStream confStream, PasswordResolver passwordResolver)
      throws InvalidConfException, IOException {
    ParamUtil.requireNonNull("confStream", confStream);
    try {
      JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
      Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
      SchemaFactory schemaFact = SchemaFactory.newInstance(
          javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
      Schema schema = schemaFact.newSchema(getClass().getResource("/xsd/pkcs11-conf.xsd"));
      unmarshaller.setSchema(schema);
      @SuppressWarnings("unchecked")
      JAXBElement<PKCS11ConfType> rootElement = (JAXBElement<PKCS11ConfType>)
          unmarshaller.unmarshal(confStream);
      PKCS11ConfType pkcs11Conf = rootElement.getValue();
      ModulesType modulesType = pkcs11Conf.getModules();

      MechnanismSetsType mechanismSets = pkcs11Conf.getMechanismSets();
      Map<String, P11ModuleConf> confs = new HashMap<>();
      for (ModuleType moduleType : modulesType.getModule()) {
        P11ModuleConf conf = new P11ModuleConf(moduleType, mechanismSets, passwordResolver);
        confs.put(conf.name(), conf);
      }

      if (!confs.containsKey(P11CryptServiceFactory.DEFAULT_P11MODULE_NAME)) {
        throw new InvalidConfException("module '"
            + P11CryptServiceFactory.DEFAULT_P11MODULE_NAME + "' is not defined");
      }
      this.moduleConfs = Collections.unmodifiableMap(confs);
      this.moduleNames = Collections.unmodifiableSet(new HashSet<>(confs.keySet()));
    } catch (JAXBException | SAXException ex) {
      final String exceptionMsg = (ex instanceof JAXBException)
          ? getMessage((JAXBException) ex) : ex.getMessage();
      LogUtil.error(LOG, ex, exceptionMsg);
      throw new InvalidConfException("invalid PKCS#11 configuration");
    } finally {
      confStream.close();
    }
  }

  public Set<String> moduleNames() {
    return moduleNames;
  }

  public P11ModuleConf moduleConf(String moduleName) {
    return moduleConfs.get(moduleName);
  }

  private static String getMessage(JAXBException ex) {
    String ret = ex.getMessage();
    if (ret == null && ex.getLinkedException() != null) {
      ret = ex.getLinkedException().getMessage();
    }
    return ret;
  }

}
