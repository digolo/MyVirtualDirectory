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
import net.sourceforge.myvd.util.SchemaUtil;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.AttributeValueAssertion;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.AttributeValueAssertionFilter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the Assertion Value filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitAssertionValueFilterAction extends GrammarAction
{
    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( InitAssertionValueFilterAction.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public InitAssertionValueFilterAction()
    {
        super( "Initialize Assertion Value filter" );
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

        // The value can be null.
        Object assertionValue = StringTools.EMPTY_BYTES;

        if ( tlv.getLength() != 0 )
        {
            assertionValue = tlv.getValue().getData();
        }

        //AttributeValueAssertionFilter terminalFilter = ( AttributeValueAssertionFilter ) searchRequest.getTerminalFilter();
        //AttributeValueAssertion assertion = terminalFilter.getAssertion();
        
        FilterNode node = searchRequest.getTerminalFilter();

        //if ( ldapMessageContainer.isBinary( assertion.getAttributeDesc() ) )
        //{
           // assertion.setAssertionValue( assertionValue );
        //	System.out.println("HERE!!!!");
        //}
        //else
        //{
            //assertion.setAssertionValue( StringTools.utf8ToString( ( byte[] ) assertionValue ) );
        byte[]  enc = ( byte[] ) assertionValue;
        	if (SchemaUtil.getSchemaUtil().isBinary(node.getName())) {
        		StringBuilder sb = new StringBuilder(enc.length * 2);
    			
    			for (int i=0; i< enc.length; i++)
    			
    			{
    			
    			sb.append(String.format("\\%02x", enc[i]));
    			
    			}
    			
    			String hex1 = sb.toString();
    			
    			node.setValue(hex1);
        	} else {
        		node.setValue(StringTools.utf8ToString( ( byte[] ) assertionValue ));
        	}
        
        	
            
            
            
          
            
            
        //}

        // We now have to get back to the nearest filter which is
        // not terminal.
        searchRequest.unstackFilters( container );

        if ( IS_DEBUG )
        {
            log.debug( "Initialize Assertion Value filter" );
        }
    }
}
