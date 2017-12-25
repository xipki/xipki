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

package org.xipki.ca.dbtool.xmlio.ocsp;

import java.io.IOException;

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspCertsWriter extends DbiXmlWriter {

    public OcspCertsWriter() throws IOException, XMLStreamException {
        super(OcspCertType.TAG_PARENT, "1");
    }

    public void add(final OcspCertType cert) throws InvalidDataObjectException, XMLStreamException {
        ParamUtil.requireNonNull("cert", cert);

        cert.validate();
        cert.writeTo(this);
    }

}
