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

package org.xipki.ca.server.api;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.xipki.audit.AuditEvent;
import org.xipki.ca.api.OperationException;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.message.CaCaps;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public interface Scep {

  boolean isOnService();

  CaCaps getCaCaps();

  ScepCaCertRespBytes getCaCertResp() throws OperationException;

  boolean supportsCertProfile(String profileName);

  ContentInfo servicePkiOperation(CMSSignedData requestContent, String certProfileName,
      String msgId, AuditEvent event) throws MessageDecodingException, OperationException;
}
