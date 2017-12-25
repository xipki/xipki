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

package org.xipki.ca.dbtool.port;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbPortFileNameIterator implements Iterator<String> {

    private static final Logger LOG = LoggerFactory.getLogger(DbPortFileNameIterator.class);

    private BufferedReader reader;

    private String nextFilename;

    public DbPortFileNameIterator(final String filename) throws IOException {
        ParamUtil.requireNonNull("filename", filename);

        this.reader = new BufferedReader(new FileReader(filename));
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
            throw new RuntimeException("could not read next file name");
        }
        return str;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("remove is not supported");
    }

    public void close() {
        try {
            reader.close();
        } catch (Throwable th) {
            LOG.error("could not close reader: {}", th.getMessage());
            LOG.error("could not close reader", th);
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
