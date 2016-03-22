/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.pkcs11proxy.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ServerCaps {
    public static final String KEY_versions = "versions";

    private final Set<Integer> versions;

    public ServerCaps(
            final Set<Integer> versions) {
        this.versions = ParamUtil.requireNonEmpty("versions", versions);
    }

    public ServerCaps(
            final byte[] caps) {
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(caps));
        } catch (IOException ex) {
            throw new RuntimeException("should not reach here");
        }
        String str = props.getProperty(KEY_versions);
        if (str == null) {
            throw new IllegalArgumentException("invalid caps '"  + new String(caps) + "'");
        }
        StringTokenizer st = new StringTokenizer(str, ", ");
        versions = new HashSet<>();
        while (st.hasMoreTokens()) {
            versions.add(Integer.parseInt(st.nextToken()));
        }
        if (versions.isEmpty()) {
            throw new IllegalArgumentException("property versions is not specified");
        }
    }

    @Override
    public String toString() {
        return getCaps();
    }

    public Set<Integer> getVersions() {
        return Collections.unmodifiableSet(versions);
    }

    public String getCaps() {
        Properties props = new Properties();
        StringBuilder sb = new StringBuilder();
        for (Integer version : versions) {
            sb.append(version).append(",");
        }
        sb.deleteCharAt(sb.length() - 1);
        props.put("version", sb.toString());
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            props.store(bout, null);
        } catch (IOException ex) {
            throw new RuntimeException("should not reach here");
        }
        return new String(bout.toByteArray());
    }
}
