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

package net.sourceforge.myvd.protocol.ldap.mina.ldap.url;


import javax.naming.NamingException;


/**
 * An LDAP URL parser.
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc2255.html">RFC 2255</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Revision: 437007 $
 */
public interface LdapUrlParser
{
    /**
     * Parses an LDAP URL.
     * 
     * @param a_urlString
     *            the LDAP URL as a String
     * @return a parsed instance of LdapUrl.
     * @throws NamingException
     *             if the URL or any one of its components is malformed.
     */
    LdapUrl parse( String a_urlString ) throws NamingException;
}
