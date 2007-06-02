/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package net.sourceforge.myvd.protocol.ldap.mina.ldap.util;


import javax.naming.NamingEnumeration;

import java.util.NoSuchElementException;


/**
 * A NamingEnumeration over a single element.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Revision: 437007 $
 */
public class SingletonEnumeration implements NamingEnumeration
{
    /** The singleton element to return */
    private final Object m_element;

    /** Can we return a element */
    private boolean m_hasMore = true;


    /**
     * Creates a NamingEnumeration over a single element.
     * 
     * @param a_element
     *            TODO
     */
    public SingletonEnumeration(final Object a_element)
    {
        m_element = a_element;
    }


    /**
     * Makes calls to hasMore to false even if we had more.
     * 
     * @see javax.naming.NamingEnumeration#close()
     */
    public void close()
    {
        m_hasMore = false;
    }


    /**
     * @see javax.naming.NamingEnumeration#hasMore()
     */
    public boolean hasMore()
    {
        return m_hasMore;
    }


    /**
     * @see javax.naming.NamingEnumeration#next()
     */
    public Object next()
    {
        if ( m_hasMore )
        {
            m_hasMore = false;
            return m_element;
        }

        throw new NoSuchElementException();
    }


    /**
     * @see java.util.Enumeration#hasMoreElements()
     */
    public boolean hasMoreElements()
    {
        return m_hasMore;
    }


    /**
     * @see java.util.Enumeration#nextElement()
     */
    public Object nextElement()
    {
        return next();
    }
}
