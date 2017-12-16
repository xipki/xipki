/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.dbtool.xmlio.ca;

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.IdentifidDbObjectType;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class UserType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "users";

    public static final String TAG_ROOT = "user";

    public static final String TAG_NAME = "name";

    public static final String TAG_ACTIVE = "active";

    public static final String TAG_PASSWORD = "password";

    private String name;

    private Boolean active;

    private String password;

    public String name() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public Boolean active() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public String password() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    @Override
    public void validate() throws InvalidDataObjectException {
        super.validate();
        assertNotBlank(TAG_NAME, name);
        assertNotNull(TAG_ACTIVE, active);
        assertNotBlank(TAG_PASSWORD, password);
    }

    @Override
    public void writeTo(final DbiXmlWriter writer)
            throws InvalidDataObjectException, XMLStreamException {
        ParamUtil.requireNonNull("writer", writer);
        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id());
        writeIfNotNull(writer, TAG_ACTIVE, active);
        writeIfNotNull(writer, TAG_NAME, name);
        writeIfNotNull(writer, TAG_PASSWORD, password);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
