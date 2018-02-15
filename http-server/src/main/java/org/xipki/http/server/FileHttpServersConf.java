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

package org.xipki.http.server;

import java.io.File;
import java.net.URL;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.xipki.httpserver.v1.jaxb.Httpservers;
import org.xipki.httpserver.v1.jaxb.ObjectFactory;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class FileHttpServersConf implements HttpServersConf {

    private String confFile;

    private Httpservers conf;

    public void setConfFile(String confFile) throws Exception {
        this.confFile = confFile;

        Object root;
        try {
            JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller jaxbUnmarshaller = context.createUnmarshaller();
            final SchemaFactory schemaFact = SchemaFactory.newInstance(
                    XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = ObjectFactory.class.getResource("/xsd/httpserver.xsd");
            jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));

            root = jaxbUnmarshaller.unmarshal(new File(confFile));
        } catch (Exception ex) {
            throw new Exception("parsing config file failed, message: " + ex.getMessage(), ex);
        }

        if (root instanceof Httpservers) {
            this.conf = (Httpservers) root;
        } else if (root instanceof JAXBElement) {
            this.conf = (Httpservers) ((JAXBElement<?>) root).getValue();
        } else {
            throw new Exception("invalid root element type");
        }
    }

    public String confFile() {
        return confFile;
    }

    public Httpservers getConf() {
        return conf;
    }

}
