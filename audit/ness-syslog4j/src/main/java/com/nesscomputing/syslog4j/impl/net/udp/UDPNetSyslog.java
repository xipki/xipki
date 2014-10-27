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

package com.nesscomputing.syslog4j.impl.net.udp;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

import com.nesscomputing.syslog4j.SyslogLevel;
import com.nesscomputing.syslog4j.SyslogRuntimeException;
import com.nesscomputing.syslog4j.impl.AbstractSyslogWriter;
import com.nesscomputing.syslog4j.impl.net.AbstractNetSyslog;

/**
 * Copied from syslog4j and patched
 *
* UDPNetSyslog is an extension of AbstractSyslog that provides support for
* UDP/IP-based syslog clients.
*
* <p>Syslog4j is licensed under the Lesser GNU Public License v2.1.  A copy
* of the LGPL license is available in the META-INF folder in all
* distributions of Syslog4j and in the base directory of the "doc" ZIP.</p>
*
* @author &lt;syslog4j@productivity.org&gt;
* @author Lijun Liao
* @version $Id: UDPNetSyslog.java,v 1.18 2010/10/27 06:18:10 cvs Exp $
*/
public class UDPNetSyslog extends AbstractNetSyslog
{
    protected DatagramSocket socket = null;

    public void initialize()
    throws SyslogRuntimeException
    {
        super.initialize();

        createDatagramSocket(true);
    }

    protected synchronized void createDatagramSocket(boolean initialize)
    {
        try
        {
            this.socket = new DatagramSocket();

        } catch (SocketException se)
        {
            if (initialize)
            {
                if (this.syslogConfig.isThrowExceptionOnInitialize())
                {
                    throw new SyslogRuntimeException(se);
                }

            } else
            {
                throw new SyslogRuntimeException(se);
            }
        }

        if (this.socket == null)
        {
            throw new SyslogRuntimeException("Cannot seem to get a Datagram socket");
        }
    }

    protected void write(SyslogLevel level, byte[] message)
    throws SyslogRuntimeException
    {
        if (this.socket == null)
        {
            createDatagramSocket(false);
        }

        InetAddress hostAddress = getHostAddress();

        DatagramPacket packet = new DatagramPacket(
            message,
            message.length,
            hostAddress,
            this.syslogConfig.getPort()
        );

        int attempts = 0;

        while(attempts != -1 && attempts < (this.netSyslogConfig.getWriteRetries() + 1))
        {
            try
            {
                this.socket.send(packet);
                /* -----BEGIN PATCH----- */
                attempts = -1;
                /* -----END PATCH----- */
            } catch (IOException ioe)
            {
                /* -----BEGIN ORIGINAL-----
                if (attempts == (this.netSyslogConfig.getWriteRetries() + 1))
                {
                    throw new SyslogRuntimeException(ioe);
                }
                -----END ORIGINAL----- */

                /* -----BEGIN PATCH----- */
                if (attempts >= (this.netSyslogConfig.getWriteRetries() + 1))
                {
                    throw new SyslogRuntimeException(ioe);
                }
                else
                {
                    attempts++;
                }
                /* -----END PATCH----- */
            }
        }
    }

    public void flush()
    throws SyslogRuntimeException
    {
        shutdown();

        createDatagramSocket(true);
    }

    public void shutdown()
    throws SyslogRuntimeException
    {
        if (this.socket != null)
        {
            this.socket.close();
            this.socket = null;
        }
    }

    public AbstractSyslogWriter getWriter()
    {
        return null;
    }

    public void returnWriter(AbstractSyslogWriter syslogWriter)
    {
        //
    }
}
