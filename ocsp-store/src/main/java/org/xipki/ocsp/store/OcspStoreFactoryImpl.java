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

package org.xipki.ocsp.store;

import org.xipki.common.ObjectCreationException;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreFactory;

/**
 * TODO.
 * @author Lijun Liao
 */

public class OcspStoreFactoryImpl implements OcspStoreFactory {

  private static final String TYPE_XIPKI_DB = "xipki-db";

  private static final String TYPE_CRL = "crl";

  @Override
  public boolean canCreateOcspStore(String type) {
    return TYPE_XIPKI_DB.equalsIgnoreCase(type) || TYPE_CRL.equalsIgnoreCase(type);
  }

  @Override
  public OcspStore newOcspStore(String type) throws ObjectCreationException {
    if (TYPE_XIPKI_DB.equalsIgnoreCase(type)) {
      return new DbCertStatusStore();
    } else if (TYPE_CRL.equalsIgnoreCase(type)) {
      return new CrlDbCertStatusStore();
    } else {
      throw new ObjectCreationException("unknown type OCSP store type " + type);
    }
  }

}
