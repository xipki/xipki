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

import org.xipki.ca.api.OperationException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OperationExceptionWithIndex extends OperationException {

  private static final long serialVersionUID = 1L;

  private final OperationException underlying;

  private final int index;

  public OperationExceptionWithIndex(int index, OperationException underlying) {
    super(underlying.getErrorCode());
    this.index = index;
    this.underlying = underlying;
  }

  @Override
  public ErrorCode getErrorCode() {
    return underlying.getErrorCode();
  }

  @Override
  public String getErrorMessage() {
    return underlying.getErrorMessage();
  }

  public int getIndex() {
    return index;
  }

}
