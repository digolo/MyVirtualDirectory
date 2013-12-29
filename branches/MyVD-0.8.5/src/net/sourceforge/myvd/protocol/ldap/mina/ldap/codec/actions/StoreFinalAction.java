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
import net.sourceforge.myvd.types.FilterNode;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SubstringFilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a final value into a substring filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreFinalAction extends GrammarAction
{
    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( StoreFinalAction.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public StoreFinalAction()
    {
        super( "Store a final value" );
    }

    /**
     * The initialization action
     */
    public void action( IAsn1Container container ) throws DecoderException
    {
        LdapMessageContainer ldapMessageContainer = ( LdapMessageContainer ) container;
        LdapMessage ldapMessage = ldapMessageContainer.getLdapMessage();
        SearchRequest searchRequest = ldapMessage.getSearchRequest();

        TLV tlv = ldapMessageContainer.getCurrentTLV();

        // Store the value.
        //SubstringFilter substringFilter = ( SubstringFilter ) searchRequest.getTerminalFilter();
        FilterNode node = searchRequest.getTerminalFilter();
        

        if ( tlv.getLength() == 0 )
        {
            log.error( "The substring final filter is empty" );
            throw new DecoderException( "The substring final filter is empty" );
        }

        String finalValue = new String( tlv.getValue().getData() );
        //substringFilter.setFinalSubstrings( finalValue );
        if (node.getValue().length() > 0 && node.getValue().charAt(node.getValue().length() - 1) == '*') {
        	node.setValue(node.getValue()  + finalValue);
        } else {
        	node.setValue(node.getValue() + '*' + finalValue);
        }
        

        // We now have to get back to the nearest filter which is
        // not terminal.
        searchRequest.unstackFilters( container );

        if ( IS_DEBUG )
        {
            log.debug( "Stored a any substring : {}", finalValue );
        }
    }
}
