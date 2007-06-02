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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.actions;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.IAsn1Container;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar.GrammarAction;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchResultReference;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURL;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURLEncodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a reference into a searchResultReference
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreReferenceAction extends GrammarAction
{
    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( StoreReferenceAction.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public StoreReferenceAction()
    {
        super( "Store a reference" );
    }

    /**
     * The initialization action
     */
    public void action( IAsn1Container container ) throws DecoderException
    {

        LdapMessageContainer ldapMessageContainer = ( LdapMessageContainer ) container;

        SearchResultReference searchResultReference = ldapMessageContainer.getLdapMessage()
            .getSearchResultReference();

        // Get the Value and store it in the BindRequest
        TLV tlv = ldapMessageContainer.getCurrentTLV();

        // We have to handle the special case of a 0 length server
        // sasl credentials
        LdapURL url = LdapURL.EMPTY_URL;

        if ( tlv.getLength() == 0 )
        {
            searchResultReference.addSearchResultReference( url );
        }
        else
        {
            try
            {
                url = new LdapURL( tlv.getValue().getData() );
                searchResultReference.addSearchResultReference( url );
            }
            catch ( LdapURLEncodingException luee )
            {
                String badUrl = new String( tlv.getValue().getData() );
                log.error( "The URL {} is not valid : {}", badUrl, luee.getMessage() );
                throw new DecoderException( "Invalid URL : " + luee.getMessage() );
            }
        }

        if ( IS_DEBUG )
        {
            log.debug( "Search reference URL found : {}", url );
        }

        // We can have an END transition
        ldapMessageContainer.grammarEndAllowed( true );

        return;
    }
}
