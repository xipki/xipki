/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.api.profile;

/**
 * @author Lijun Liao
 */

public enum KeyUsage
{
    digitalSignature  (0, "digitalSignature"),
    contentCommitment (1, "contentCommitment", "nonRepudiation"),
    keyEncipherment   (2, "keyEncipherment"),
    dataEncipherment  (3, "dataEncipherment"),
    keyAgreement      (4, "keyAgreement"),
    keyCertSign       (5, "keyCertSign"),
    cRLSign           (6, "cRLSign"),
    encipherOnly      (7, "encipherOnly"),
    decipherOnly      (8, "decipherOnly");

    private int bit;
    private String[] names;

    private KeyUsage(int bit, String... names)
    {
        this.bit = bit;
        this.names = names;
    }

    public static KeyUsage getKeyUsage(String usage)
    {
        if(usage == null)
        {
            return null;
        }

        for(KeyUsage ku : KeyUsage.values())
        {
            for(String name : ku.names)
            {
                if(name.equals(usage))
                {
                    return ku;
                }
            }
        }

        return null;
    }

    public static KeyUsage getKeyUsage(int bit)
    {
        for(KeyUsage ku : KeyUsage.values())
        {
            if(ku.bit == bit)
            {
                return ku;
            }
        }

        return null;
    }

    public String getName()
    {
        return names[0];
    }
}
