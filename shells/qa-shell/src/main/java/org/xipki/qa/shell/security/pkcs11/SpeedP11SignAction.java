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

package org.xipki.qa.shell.security.pkcs11;

import org.apache.karaf.shell.api.action.Option;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class SpeedP11SignAction extends SpeedP11Action {

  @Option(name = "--key-present", description = "the PKCS#11 key is present")
  protected Boolean keyPresent = Boolean.FALSE;

  @Option(name = "--key-label", description = "label of the PKCS#11 key")
  protected String keyLabel;

}
