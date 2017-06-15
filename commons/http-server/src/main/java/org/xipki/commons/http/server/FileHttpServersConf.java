/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.commons.http.server;

import java.io.File;
import java.net.URL;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.xipki.httpserver.v1.Httpservers;
import org.xipki.httpserver.v1.ObjectFactory;

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
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = ObjectFactory.class.getResource("/xsd/httpserver.xsd");
            jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));

            root = jaxbUnmarshaller.unmarshal(new File(confFile));
        } catch (Exception ex) {
            throw new Exception("parsing configuration file failed, message: " + ex.getMessage(),
                    ex);
        }

        if (root instanceof Httpservers) {
            this.conf = (Httpservers) root;
        } else if (root instanceof JAXBElement) {
            this.conf = (Httpservers) ((JAXBElement<?>) root).getValue();
        } else {
            throw new Exception("invalid root element type");
        }
    }

    public String getConfFile() {
        return confFile;
    }

    public Httpservers getConf() {
        return conf;
    }

}
