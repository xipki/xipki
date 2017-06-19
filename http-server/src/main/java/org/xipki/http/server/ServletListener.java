/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.http.server;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.http.servlet.HttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.ServletURIPool;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ServletListener {

    private static final Logger LOG = LoggerFactory.getLogger(ServletListener.class);

    private final ConcurrentMap<HttpServlet, String> servletAliasMap = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, HttpServlet> aliasServletMap = new ConcurrentHashMap<>();

    private final Set<String> aliases = new HashSet<>();

    // Don't change the method signature, exactly this is required by the OSGi blueprint service
    public void register(HttpServlet servlet, Map<?, ?> properties) {
        if (properties == null) {
            LOG.info("registerServlet invoked with null properties, ingore it");
            return;
        }

        Object propValue = properties.get("alias");
        if (!(propValue instanceof String)) {
            LOG.info("registerServlet invoked with invalid type ({}) of alias, ingore it",
                    propValue.getClass().getName());
            return;
        }

        register(servlet, (String) propValue);
    }

    /**
     * Register the servlet.
     *
     * @param servlet
     *          The servlet to be registered.
     * @param aliasList
     *          Comma or space separated list of aliases under which the servlet will be registered.
     */
    public void register(HttpServlet servlet, String aliasList) {
        //might be null if dependency is optional
        if (servlet == null) {
            LOG.info("registerServlet invoked with null servlet, ingore it");
            return;
        }

        if (aliasList.isEmpty()) {
            LOG.info("registerServlet invoked with empty alias, ingore it");
            return;
        }

        StringTokenizer tokenizer = new StringTokenizer(aliasList, ", ");
        List<String> list = new ArrayList<>(tokenizer.countTokens());
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            if (!token.isEmpty()) {
                list.add(token);
            }
        }

        for (String alias : list) {
            if (alias.charAt(0) != '/') {
                alias = "/" + alias;
            }

            if (alias.length() > 1 && alias.charAt(alias.length() - 1) == '/') {
                alias = alias.substring(0, alias.length() - 1);
            }

            if (aliases.contains(alias)) {
                LOG.info("registerServlet invoked with duplicated alias {}, ingore it", alias);
                continue;
            }

            String previousAlias = servletAliasMap.put(servlet, alias);
            aliases.add(alias);
            aliasServletMap.put(alias, servlet);

            if (previousAlias != null) {
                aliases.remove(previousAlias);
                aliasServletMap.remove(previousAlias);
                LOG.info("re-register HttpServet {} for alias {} (previous {})",
                        servlet, alias, previousAlias);
            } else {
                LOG.info("register HttpServet {} for alias {}", servlet, alias);
            }
        }
    }

    public void unregister(HttpServlet servlet) {
        //might be null if dependency is optional
        if (servlet == null) {
            LOG.debug("unregisterServlet invoked with null.");
            return;
        }

        String alias = servletAliasMap.remove(servlet);
        if (alias != null) {
            aliases.remove(alias);
            aliasServletMap.remove(alias);
            LOG.info("removed HttpServlet for {}", servlet);
        } else {
            LOG.info("no HttpServlet found to remove for {}", servlet);
        }
    }

    public Object[] getServlet(String rawPath) throws URISyntaxException {
        String alias = null;
        String uriText = null;

        for (String m : aliases) {
            if (m.equals("/")) {
                alias = m;
                uriText = rawPath;
                break;
            }

            if (rawPath.startsWith(m)) {
                int len = rawPath.length();
                int mLen = m.length();
                if (len == mLen) {
                    uriText = "/";
                    alias = m;
                } else {
                    char ch = rawPath.charAt(mLen);
                    if (ch == '/') {
                        uriText = (len == mLen + 1) ? "/" : rawPath.substring(mLen);
                        alias = m;
                    } else if (ch == '?') {
                        uriText = rawPath.substring(mLen);
                        alias = m;
                    }
                }
            }

            if (alias != null) {
                break;
            }
        }

        if (alias == null) {
            return null;
        }

        ServletURI servletUri = ServletURIPool.getServletURI(uriText);
        HttpServlet servlet = aliasServletMap.get(alias);
        return new Object[]{servletUri, servlet};
    }

}
