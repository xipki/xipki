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

package org.xipki.ocsp.client.shell;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.client.api.InvalidOcspResponseException;
import org.xipki.ocsp.client.api.OcspResponseException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspUtils {

  private OcspUtils() {
  }

  public static BasicOCSPResp extractBasicOcspResp(OCSPResp response)
      throws OcspResponseException {
    ParamUtil.requireNonNull("response", response);
    int status = response.getStatus();
    if (status == 0) {
      BasicOCSPResp basicOcspResp;
      try {
        basicOcspResp = (BasicOCSPResp) response.getResponseObject();
      } catch (OCSPException ex) {
        throw new InvalidOcspResponseException(ex.getMessage(), ex);
      }
      return basicOcspResp;
    } else {
      throw new OcspResponseUnsuccessfulException(status);
    }
  }

}
