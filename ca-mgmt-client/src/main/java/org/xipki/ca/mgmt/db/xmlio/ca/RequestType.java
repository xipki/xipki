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

package org.xipki.ca.mgmt.db.xmlio.ca;

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.mgmt.db.xmlio.DbiXmlWriter;
import org.xipki.ca.mgmt.db.xmlio.IdentifidDbObjectType;
import org.xipki.ca.mgmt.db.xmlio.InvalidDataObjectException;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestType extends IdentifidDbObjectType {

  public static final String TAG_PARENT = "requests";

  public static final String TAG_ROOT = "request";

  public static final String TAG_UPDATE = "update";

  private Long update;

  private String file;

  public Long getUpdate() {
    return update;
  }

  public void setUpdate(Long update) {
    this.update = update;
  }

  public String getFile() {
    return file;
  }

  public void setFile(String file) {
    this.file = file;
  }

  @Override
  public void validate() throws InvalidDataObjectException {
    super.validate();
    assertNotNull(TAG_UPDATE, update);
    assertNotBlank(TAG_FILE, file);
  }

  @Override
  public void writeTo(DbiXmlWriter writer) throws InvalidDataObjectException, XMLStreamException {
    ParamUtil.requireNonNull("writer", writer);

    validate();

    writer.writeStartElement(TAG_ROOT);
    writeIfNotNull(writer, TAG_ID, getId());
    writeIfNotNull(writer, TAG_UPDATE, update);
    writeIfNotNull(writer, TAG_FILE, file);
    writer.writeEndElement();
    writer.writeNewline();
  }

}
