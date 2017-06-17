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

package org.xipki.pki.ca.server.impl;

import java.util.HashMap;
import java.util.Map;

import org.xipki.pki.ca.api.NameId;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CaIdNameMap {

    private final Map<Integer, NameId> idCertprofileMap = new HashMap<>();

    private final Map<Integer, NameId> idPublisherMap = new HashMap<>();

    private final Map<Integer, NameId> idRequestorMap = new HashMap<>();

    private final Map<Integer, NameId> idCaMap = new HashMap<>();

    private final Map<String, NameId> nameCertprofileMap = new HashMap<>();

    private final Map<String, NameId> namePublisherMap = new HashMap<>();

    private final Map<String, NameId> nameRequestorMap = new HashMap<>();

    private final Map<String, NameId> nameCaMap = new HashMap<>();

    public void addCertprofile(final NameId nameId) {
        idCertprofileMap.put(nameId.id(), nameId);
        nameCertprofileMap.put(nameId.name(), nameId);
    }

    public void addPublisher(final NameId nameId) {
        idPublisherMap.put(nameId.id(), nameId);
        namePublisherMap.put(nameId.name(), nameId);
    }

    public void addRequestor(final NameId nameId) {
        idRequestorMap.put(nameId.id(), nameId);
        nameRequestorMap.put(nameId.name(), nameId);
    }

    public void addCa(final NameId nameId) {
        idCaMap.put(nameId.id(), nameId);
        nameCaMap.put(nameId.name(), nameId);
    }

    public NameId certprofile(int id) {
        return idCertprofileMap.get(id);
    }

    public NameId certprofile(String name) {
        return nameCertprofileMap.get(name.toUpperCase());
    }

    public NameId publisher(int id) {
        return idPublisherMap.get(id);
    }

    public NameId publisher(String name) {
        return namePublisherMap.get(name.toUpperCase());
    }

    public NameId requestor(int id) {
        return idRequestorMap.get(id);
    }

    public NameId requestor(String name) {
        return nameRequestorMap.get(name.toUpperCase());
    }

    public NameId ca(int id) {
        return idCaMap.get(id);
    }

    public NameId ca(String name) {
        return nameCaMap.get(name.toUpperCase());
    }

    public String certprofileName(int id) {
        NameId nid = idCertprofileMap.get(id);
        return (nid == null) ? null : nid.name();
    }

    public String publisherName(int id) {
        NameId nid = idPublisherMap.get(id);
        return (nid == null) ? null : nid.name();
    }

    public String requestorName(int id) {
        NameId nid = idRequestorMap.get(id);
        return (nid == null) ? null : nid.name();
    }

    public String caName(int id) {
        NameId nid = idCaMap.get(id);
        return (nid == null) ? null : nid.name();
    }

    public void clearCertprofile() {
        idCertprofileMap.clear();
        nameCertprofileMap.clear();
    }

    public void clearPublisher() {
        idPublisherMap.clear();
        namePublisherMap.clear();
    }

    public void clearRequestor() {
        idRequestorMap.clear();
        nameRequestorMap.clear();
    }

    public void clearCa() {
        idCaMap.clear();
        nameCaMap.clear();
    }

    public NameId removeCertprofile(int id) {
        NameId ident = idCertprofileMap.remove(id);
        if (ident != null) {
            nameCertprofileMap.remove(ident.name());
        }
        return ident;
    }

    public NameId removeCertprofile(String name) {
        NameId ident = nameCertprofileMap.remove(name.toUpperCase());
        if (ident != null) {
            idCertprofileMap.remove(ident.id());
        }
        return ident;
    }

    public NameId removePublisher(int id) {
        NameId ident = idPublisherMap.remove(id);
        if (ident != null) {
            namePublisherMap.remove(ident.name());
        }
        return ident;
    }

    public NameId removePublisher(String name) {
        NameId ident = namePublisherMap.remove(name.toUpperCase());
        if (ident != null) {
            idPublisherMap.remove(ident.id());
        }
        return ident;
    }

    public NameId removeRequestor(int id) {
        NameId ident = idRequestorMap.remove(id);
        if (ident != null) {
            nameRequestorMap.remove(ident.name());
        }
        return ident;
    }

    public NameId removeRequestor(String name) {
        NameId ident = nameRequestorMap.remove(name.toUpperCase());
        if (ident != null) {
            idRequestorMap.remove(ident.id());
        }
        return ident;
    }

    public NameId removeCa(int id) {
        NameId ident = idCaMap.remove(id);
        if (ident != null) {
            nameCaMap.remove(ident.name());
        }
        return ident;
    }

    public NameId removeCa(String name) {
        NameId ident = nameCaMap.remove(name.toUpperCase());
        if (ident != null) {
            idCaMap.remove(ident.id());
        }
        return ident;
    }

}
