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


import java.util.List;

import javax.naming.Name;

import net.sourceforge.myvd.types.Filter;




/**
 * A parsed LDAP URL.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Revision: 437007 $
 */
public interface LdapUrl
{
    /**
     * Gets the distinguished name of this LdapUrl.
     * 
     * @return the non-normalized Dn
     */
    Name getName();


    /**
     * Gets the hostname component of this LdapUrl.
     * 
     * @return the hostname of the server.
     */
    String getHostName();


    /**
     * Gets the port component of this LdapUrl.
     * 
     * @return the port number component of the LdapUrl.
     */
    int getPort();


    /**
     * Gets the filter component of this LdapUrl as a filter expression tree.
     * 
     * @return the filter expression tree's root node.
     */
    Filter getFilter();


    /**
     * Gets the attributes component of this LdapUrl.
     * 
     * @return a List containing the attribute names as Strings to return in the
     *         search results if this LdapUrl represents a search. If attributes
     *         are not specified the list will be empty.
     */
    List getAttributes();


    /**
     * Gets the extensions component of this LdapUrl. TODO can't say I know what
     * this is at the moment
     * 
     * @return a List containing the extensions
     */
    List getExtensions();


    /**
     * Gets the scope of the search if this LdapUrl represents a search URL. The
     * values returned are defined within the JNDI SearchControls class.
     * 
     * @see javax.naming.directory.SearchControls#OBJECT_SCOPE
     * @see javax.naming.directory.SearchControls#ONELEVEL_SCOPE
     * @see javax.naming.directory.SearchControls#SUBTREE_SCOPE
     * @return the scope of the search.
     */
    int getScope();


    /**
     * Gets whether or not secure ldaps scheme with SSL is used or normal ldap
     * scheme is used.
     * 
     * @return true if ldaps is the scheme, false if it is ldap
     */
    boolean isSecure();
}
