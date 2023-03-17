// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.slf4j.Logger;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.util.SqlUtil;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Base class for the OCSP CertStore database importer.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class AbstractOcspCertstoreDbImporter extends DbPorter {

  protected static final String MSG_CERTS_FINISHED = "certs.finished";

  protected static final String SQL_ADD_CRLINFO = SqlUtil.buildInsertSql("CRL_INFO", "ID,NAME,INFO");

  protected static final String SQL_ADD_ISSUER = SqlUtil.buildInsertSql("ISSUER",
      "ID,SUBJECT,NBEFORE,NAFTER,S1C,REV_INFO,CERT,CRL_ID");

  protected static final String SQL_ADD_CERT = SqlUtil.buildInsertSql("CERT",
      "ID,IID,SN,LUPDATE,NBEFORE,NAFTER,REV,RR,RT,RIT,HASH,SUBJECT,CRL_ID");

  AbstractOcspCertstoreDbImporter(DataSourceWrapper datasource, String srcDir, AtomicBoolean stopMe)
      throws Exception {
    super(datasource, srcDir, stopMe);
  }

  protected String sha1(byte[] data) {
    return HashAlgo.SHA1.base64Hash(data);
  }

  protected void deleteCertGreaterThan(long id, Logger log) {
    deleteFromTableWithLargerId("CERT", "ID", id, log);
  }

}
