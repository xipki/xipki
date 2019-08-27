/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.mgmt.db.port;

import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;

/**
 * Base class for the OCSP CertStore database importer.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class AbstractOcspCertstoreDbImporter extends DbPorter {

  protected static final String MSG_CERTS_FINISHED = "certs.finished";

  protected static final String SQL_ADD_CRLINFO =
      "INSERT INTO CRL_INFO (ID,NAME,INFO) VALUES (?,?,?)";

  protected static final String SQL_ADD_ISSUER =
      "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,REV_INFO,CERT,CRL_ID) "
      + "VALUES (?,?,?,?,?,?,?,?)";

  protected static final String SQL_ADD_CERT =
      "INSERT INTO CERT (ID,IID,SN,LUPDATE,NBEFORE,NAFTER,REV,RR,RT,RIT,HASH,SUBJECT,CRL_ID)"
      + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";

  protected static final String SQL_DEL_CERT = "DELETE FROM CERT WHERE ID>?";

  AbstractOcspCertstoreDbImporter(DataSourceWrapper datasource, String srcDir, AtomicBoolean stopMe)
      throws Exception {
    super(datasource, srcDir, stopMe);
  }

  protected String sha1(byte[] data) {
    return HashAlgo.SHA1.base64Hash(data);
  }

  protected String sha256(byte[] data) {
    return HashAlgo.SHA256.base64Hash(data);
  }

  protected String sha3_256(byte[] data) {
    return HashAlgo.SHA3_256.base64Hash(data);
  }

  protected void deleteCertGreatherThan(long id, Logger log) {
    deleteFromTableWithLargerId("CERT", "ID", id, log);
  }

}
