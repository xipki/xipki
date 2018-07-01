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

package org.xipki.security.shell.pkcs11;

import java.util.List;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11NewKeyControl;
import org.xipki.security.shell.pkcs11.completer.P11KeyUsageCompleter;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Hex;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11KeyGenAction extends P11SecurityAction {

  @Option(name = "--id", description = "id of the PKCS#11 objects")
  private String hexId;

  @Option(name = "--label", required = true, description = "label of the PKCS#11 objects")
  protected String label;

  @Option(name = "--extractable", aliases = {"-x"},
      description = "whether the key is extractable, valid values are yes|no|true|false")
  private String extractable;

  @Option(name = "--sensitive",
      description = "whether the key is sensitive, valid values are yes|no|true|false")
  private String sensitive;

  @Option(name = "--key-usage", multiValued = true,
      description = "key usage of the private key")
  @Completion(P11KeyUsageCompleter.class)
  private List<String> keyusages;

  protected void finalize(String keyType, P11IdentityId identityId) throws Exception {
    ParamUtil.requireNonNull("identityId", identityId);
    println("generated " + keyType + " key \"" + identityId + "\"");
  }

  protected P11NewKeyControl getControl() throws IllegalCmdParamException {
    byte[] id = (hexId == null) ? null : Hex.decode(hexId);
    P11NewKeyControl control = new P11NewKeyControl(id, label);
    if (StringUtil.isNotBlank(extractable)) {
      control.setExtractable(isEnabled(extractable, false, "extractable"));
    }
    if (StringUtil.isNotBlank(sensitive)) {
      control.setSensitive(isEnabled(sensitive, false, "sensitive"));
    }
    if (CollectionUtil.isNonEmpty(keyusages)) {
      control.setUsages(P11KeyUsageCompleter.parseUsages(keyusages));
    }

    return control;
  }

}
