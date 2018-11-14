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

package org.xipki.ca.mgmt.db.port;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.LogUtil;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbPortFileNameIterator implements Iterator<String>, Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(DbPortFileNameIterator.class);

  private BufferedReader reader;

  private String nextFilename;

  public DbPortFileNameIterator(String filename) throws IOException {
    Args.notNull(filename, "filename");

    this.reader = Files.newBufferedReader(Paths.get(filename));
    this.nextFilename = readNextFilenameLine();
  }

  @Override
  public boolean hasNext() {
    return nextFilename != null;
  }

  @Override
  public String next() {
    String str = nextFilename;
    nextFilename = null;
    try {
      nextFilename = readNextFilenameLine();
    } catch (IOException ex) {
      throw new IllegalStateException("could not read next file name");
    }
    return str;
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException("remove is not supported");
  }

  @Override
  public void close() {
    try {
      reader.close();
    } catch (Throwable th) {
      LogUtil.error(LOG, th,"could not close reader");
    }
  }

  private String readNextFilenameLine() throws IOException {
    String line;
    while ((line = reader.readLine()) != null) {
      line = line.trim();
      if (StringUtil.isBlank(line) || line.startsWith("#") || !line.endsWith(".zip")) {
        continue;
      }
      return line;
    }

    return null;
  }

}
