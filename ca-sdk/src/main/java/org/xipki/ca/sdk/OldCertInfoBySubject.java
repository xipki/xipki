/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class OldCertInfoBySubject extends OldCertInfo {

  private byte[] subject;

  private byte[] san;

  public byte[] getSubject() {
    return subject;
  }

  public void setSubject(byte[] subject) {
    this.subject = subject;
  }

  public byte[] getSan() {
    return san;
  }

  public void setSan(byte[] san) {
    this.san = san;
  }
}
