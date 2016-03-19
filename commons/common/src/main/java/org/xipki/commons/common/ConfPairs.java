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

package org.xipki.commons.common;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ConfPairs {

    public static final char NAME_TERM = '=';

    public static final char TOKEN_TERM = ',';

    private final Map<String, String> pairs = new HashMap<>();

    public ConfPairs(
            final String name,
            final String value) {
        putPair(name, value);
    }

    public ConfPairs() {
    }

    public ConfPairs(
            final String confPairs) {
        ParamUtil.requireNonBlank("encodedConfPairs", confPairs);
        int len = confPairs.length();
        List<String> tokens = new LinkedList<>();

        StringBuilder tokenBuilder = new StringBuilder();

        for (int i = 0; i < len;) {
            char ch = confPairs.charAt(i);
            if (TOKEN_TERM == ch) {
                if (tokenBuilder.length() > 0) {
                    tokens.add(tokenBuilder.toString());
                }
                // reset tokenBuilder
                tokenBuilder = new StringBuilder();
                i++;
                continue;
            }

            if ('\\' == ch) {
                if (i == len - 1) {
                    throw new IllegalArgumentException("invalid ConfPairs '" + confPairs + "'");
                }

                tokenBuilder.append(ch);
                ch = confPairs.charAt(i + 1);
                i++;
            }

            tokenBuilder.append(ch);
            i++;
        }

        if (tokenBuilder.length() > 0) {
            tokens.add(tokenBuilder.toString());
        }

        for (String token : tokens) {
            int termPosition = -1;
            len = token.length();
            for (int i = 0; i < len;) {
                char ch = token.charAt(i);
                if (ch == NAME_TERM) {
                    termPosition = i;
                    break;
                }

                if ('\\' == ch) {
                    if (i == len - 1) {
                        throw new IllegalArgumentException("invalid ConfPairs '" + confPairs + "'");
                    }

                    i += 2;
                } else {
                    i++;
                }
            }

            if (termPosition < 1) {
                throw new IllegalArgumentException("invalid ConfPair '" + token + "'");
            }

            tokenBuilder = new StringBuilder();
            for (int i = 0; i < termPosition;) {
                char ch = token.charAt(i);
                if ('\\' == ch) {
                    if (i == termPosition - 1) {
                        throw new IllegalArgumentException("invalid ConfPair '" + confPairs + "'");
                    }

                    i += 2;
                } else {
                    tokenBuilder.append(ch);
                    i++;
                }
            }

            String name = tokenBuilder.toString();

            tokenBuilder = new StringBuilder();
            for (int i = termPosition + 1; i < len;) {
                char ch = token.charAt(i);
                if ('\\' == ch) {
                    if (i == len - 1) {
                        throw new IllegalArgumentException("invalid ConfPair '" + confPairs + "'");
                    }

                    ch = token.charAt(i + 1);
                    i++;
                }

                tokenBuilder.append(ch);
                i++;
            }

            String value = tokenBuilder.toString();
            pairs.put(name, value);
        }
    } // constructor

    public void putPair(
            final String name,
            final String value) {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("value", value);

        char ch = name.charAt(0);
        if (ch >= '0' && ch <= '9') {
            throw new IllegalArgumentException("name begin with " + ch);
        }
        pairs.put(name, value);
    }

    public void removePair(
            final String name) {
        ParamUtil.requireNonNull("name", name);
        pairs.remove(name);
    }

    public String getValue(
            final String name) {
        ParamUtil.requireNonNull("name", name);
        return pairs.get(name);
    }

    public Set<String> getNames() {
        return Collections.unmodifiableSet(pairs.keySet());
    }

    public String getEncoded() {
        StringBuilder sb = new StringBuilder();
        List<String> names = new LinkedList<>();
        for (String name : pairs.keySet()) {
            String value = pairs.get(name);
            if (value.length() <= 100) {
                names.add(name);
            }
        }
        Collections.sort(names);

        for (String name : pairs.keySet()) {
            if (!names.contains(name)) {
                names.add(name);
            }
        }

        for (String name : names) {
            String value = pairs.get(name);
            sb.append(encodeNameOrValue(name));
            sb.append(NAME_TERM);
            sb.append(value == null
                    ? ""
                    : encodeNameOrValue(value));
            sb.append(TOKEN_TERM);
        }

        if (sb.length() > 0) {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    } // method getEncoded

    @Override
    public String toString() {
        return getEncoded();
    }

    @Override
    public int hashCode() {
        return getEncoded().hashCode();
    }

    @Override
    public boolean equals(
            final Object obj) {
        if (!(obj instanceof ConfPairs)) {
            return false;
        }

        ConfPairs cp = (ConfPairs) obj;
        return pairs.equals(cp.pairs);
    }

    private static String encodeNameOrValue(
            final String str) {
        if (str.indexOf(NAME_TERM) == -1 && str.indexOf(TOKEN_TERM) == -1) {
            return str;
        }

        final int n = str.length();
        StringBuilder sb = new StringBuilder(n + 1);
        for (int i = 0; i < n; i++) {
            char ch = str.charAt(i);
            if (ch == NAME_TERM || ch == TOKEN_TERM) {
                sb.append('\\');
            }
            sb.append(ch);
        }
        return sb.toString();
    }

}
