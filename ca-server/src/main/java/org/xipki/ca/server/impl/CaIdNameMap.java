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

package org.xipki.ca.server.impl;

import java.util.HashMap;
import java.util.Map;

import org.xipki.ca.api.NameId;

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

    public void addCertprofile(NameId nameId) {
        idCertprofileMap.put(nameId.id(), nameId);
        nameCertprofileMap.put(nameId.name(), nameId);
    }

    public void addPublisher(NameId nameId) {
        idPublisherMap.put(nameId.id(), nameId);
        namePublisherMap.put(nameId.name(), nameId);
    }

    public void addRequestor(NameId nameId) {
        idRequestorMap.put(nameId.id(), nameId);
        nameRequestorMap.put(nameId.name(), nameId);
    }

    public void addCa(NameId nameId) {
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
