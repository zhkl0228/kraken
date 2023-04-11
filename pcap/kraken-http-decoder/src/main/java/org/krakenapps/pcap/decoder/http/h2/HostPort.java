//
//  ========================================================================
//  Copyright (c) 1995-2017 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.krakenapps.pcap.decoder.http.h2;

/**
 * Parse an authority string into Host and Port
 * <p>Parse a string in the form "host:port", handling IPv4 an IPv6 hosts</p>
 *
 * <p>The System property "org.eclipse.jetty.util.HostPort.STRIP_IPV6" can be set to a boolean
 * value to control of the square brackets are stripped off IPv6 addresses (default true).</p>
 */
public class HostPort
{
    private final static boolean STRIP_IPV6 = Boolean.parseBoolean(System.getProperty("org.eclipse.jetty.util.HostPort.STRIP_IPV6","true"));

    private final String _host;
    private final int _port;

    public HostPort(String authority) throws IllegalArgumentException
    {
        if (authority==null)
            throw new IllegalArgumentException("No Authority");
        try
        {
            if (authority.isEmpty())
            {
                _host=authority;
                _port=0;
            }
            else if (authority.charAt(0)=='[')
            {
                // ipv6reference
                int close=authority.lastIndexOf(']');
                if (close<0)
                    throw new IllegalArgumentException("Bad IPv6 host");
                _host=STRIP_IPV6?authority.substring(1,close):authority.substring(0,close+1);

                if (authority.length()>close+1)
                {
                    if (authority.charAt(close+1)!=':')
                        throw new IllegalArgumentException("Bad IPv6 port");
                    _port=toInt(authority,close+2);
                }
                else
                    _port=0;
            }
            else
            {
                // ipv4address or hostname
                int c = authority.lastIndexOf(':');
                if (c>=0)
                {
                    _host=authority.substring(0,c);
                    _port=toInt(authority,c+1);
                }
                else
                {
                    _host=authority;
                    _port=0;
                }
            }
        }
        catch (IllegalArgumentException iae)
        {
            throw iae;
        }
        catch(final Exception ex)
        {
            throw new IllegalArgumentException("Bad HostPort")
            {
                {initCause(ex);}
            };
        }
        if(_port<0)
            throw new IllegalArgumentException("Bad port");
    }

    /**
     * Convert String to an integer. Parses up to the first non-numeric character. If no number is found an IllegalArgumentException is thrown
     *
     * @param string A String containing an integer.
     * @param from The index to start parsing from
     * @return an int
     */
    private static int toInt(String string,int from)
    {
        int val = 0;
        boolean started = false;
        boolean minus = false;

        for (int i = from; i < string.length(); i++)
        {
            char b = string.charAt(i);
            if (b <= ' ')
            {
                if (started)
                    break;
            }
            else if (b >= '0' && b <= '9')
            {
                val = val * 10 + (b - '0');
                started = true;
            }
            else if (b == '-' && !started)
            {
                minus = true;
            }
            else
                break;
        }

        if (started)
            return minus?(-val):val;
        throw new NumberFormatException(string);
    }

    /* ------------------------------------------------------------ */
    /** Get the host.
     * @return the host
     */
    public String getHost()
    {
        return _host;
    }

    /* ------------------------------------------------------------ */
    /** Get the port.
     * @return the port
     */
    public int getPort()
    {
        return _port;
    }

    /* ------------------------------------------------------------ */
    /** Get the port.
     * @param defaultPort, the default port to return if a port is not specified
     * @return the port
     */
    public int getPort(int defaultPort)
    {
        return _port>0?_port:defaultPort;
    }
}