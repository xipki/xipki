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

package org.xipki.ca.server;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SqlColumn {

  public static enum ColumnType {
    INT,
    STRING,
    BOOL
  }

  private ColumnType type;
  private String name;
  private Object value;
  private boolean sensitive;
  private boolean signerConf;

  public SqlColumn(ColumnType type, String name, Object value) {
    this(type, name, value, false, false);
  }

  public SqlColumn(ColumnType type, String name, Object value, boolean sensitive,
      boolean signerConf) {
    this.type = Args.notNull(type, "type");
    this.name = Args.notNull(name, "name");
    this.value = value;
    this.sensitive = sensitive;
    this.signerConf = signerConf;
  }

  public ColumnType getType() {
    return type;
  }

  public String getName() {
    return name;
  }

  public Object getValue() {
    return value;
  }

  public boolean isSensitive() {
    return sensitive;
  }

  public boolean isSignerConf() {
    return signerConf;
  }

}
