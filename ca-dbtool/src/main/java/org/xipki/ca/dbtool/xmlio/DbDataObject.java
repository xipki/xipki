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

package org.xipki.ca.dbtool.xmlio;

import javax.xml.stream.XMLStreamException;

import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DbDataObject {

    protected DbDataObject() {
    }

    protected void assertNotBlank(final String name, final String value)
            throws InvalidDataObjectException {
        if (StringUtil.isBlank(value)) {
            throw new InvalidDataObjectException(name + " must not be blank");
        }
    }

    protected void assertNotNull(final String name, final Object value)
            throws InvalidDataObjectException {
        if (value == null) {
            throw new InvalidDataObjectException(name + " must not be null");
        }
    }

    protected static void writeIfNotNull(final DbiXmlWriter writer, final String tag,
            final Object value) throws XMLStreamException, InvalidDataObjectException {
        if (value == null) {
            return;
        }

        String valueS;
        if (value instanceof String) {
            valueS = (String) value;
        } else if (value instanceof Number) {
            valueS = value.toString();
        } else if (value instanceof Boolean) {
            valueS = value.toString();
        } else {
            throw new InvalidDataObjectException("value is not a String or Number");
        }

        writer.writeElement(tag, valueS);
    }

    public abstract void validate() throws InvalidDataObjectException;

    /**
     *
     * @param writer
     *          Writer. Must not be {@code null}.
     *
     */
    public abstract void writeTo(DbiXmlWriter writer)
            throws InvalidDataObjectException, XMLStreamException;

}
