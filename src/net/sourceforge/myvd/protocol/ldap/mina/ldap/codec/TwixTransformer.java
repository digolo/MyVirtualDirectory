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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;



import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Filter;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.Asn1Object;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.primitives.OID;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.util.Asn1StringUtils;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.abandon.AbandonRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.add.AddRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.add.AddResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.bind.BindRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.bind.BindResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.bind.SaslCredentials;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.bind.SimpleAuthentication;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.compare.CompareRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.compare.CompareResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.del.DelRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.del.DelResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.ExtendedRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.ExtendedResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.modify.ModifyRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.modify.ModifyResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.modifyDn.ModifyDNRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.modifyDn.ModifyDNResponse;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.PresentFilter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchResultDone;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchResultEntry;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchResultReference;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SubstringFilter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls.PSearchControl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls.SubEntryControl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURL;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURLEncodingException;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AbandonRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AddRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AddResponseImpl;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.BindRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.BindResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.CompareRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.CompareResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ControlImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.DeleteRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.DeleteResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.DerefAliasesEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ExtendedRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ExtendedResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.LdapResultImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.Message;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ModifyDnRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ModifyDnResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ModifyRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ModifyResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.PersistentSearchControl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.Referral;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ReferralImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseDoneImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseEntry;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseReferenceImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SubentriesControl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.UnbindRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.extended.GracefulShutdownRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.spi.Provider;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.spi.TransformerSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Twix to Snickers Message transformer.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 *         $Rev: 494173 $
 */
public class TwixTransformer implements TransformerSpi
{
    /** The logger */
    private static Logger log = LoggerFactory.getLogger( TwixTransformer.class );

    /** A speedup for logger */
    private static final boolean IS_DEBUG = log.isDebugEnabled();
    
    /** the provider this transformer is part of */
    private final Provider provider;


    /**
     * Creates a passthrough transformer that really does nothing at all.
     * 
     * @param provider the provider for this transformer
     */
    public TwixTransformer(Provider provider)
    {
        this.provider = provider;
    }


    /**
     * Gets the Provider associated with this SPI implementation object.
     * 
     * @return Provider.
     */
    public Provider getProvider()
    {
        return provider;
    }


    /**
     * Transform an AbandonRequest message from a TwixMessage to a
     * SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers AbandonRequestImpl
     */
    private Message transformAbandonRequest( LdapMessage twixMessage, int messageId )
    {
        AbandonRequestImpl snickersMessage = new AbandonRequestImpl( messageId );
        AbandonRequest abandonRequest = twixMessage.getAbandonRequest();

        // Twix : int abandonnedMessageId -> Snickers : int abandonId
        snickersMessage.setAbandoned( abandonRequest.getAbandonedMessageId() );

        return snickersMessage;
    }


    /**
     * Transform an AddRequest message from a TwixMessage to a SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers AddRequestImpl
     */
    private Message transformAddRequest( LdapMessage twixMessage, int messageId )
    {
        AddRequestImpl snickersMessage = new AddRequestImpl( messageId );
        AddRequest addRequest = twixMessage.getAddRequest();

        // Twix : LdapDN entry -> Snickers : String name
        snickersMessage.setEntry( addRequest.getEntry() );

        // Twix : Attributes attributes -> Snickers : Attributes entry
        snickersMessage.setAttribSet(addRequest.getAttributeSet());

        return snickersMessage;
    }


    /**
     * Transform a BindRequest message from a TwixMessage to a SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers BindRequestImpl
     */
    private Message transformBindRequest( LdapMessage twixMessage, int messageId )
    {
        BindRequestImpl snickersMessage = new BindRequestImpl( messageId );
        BindRequest bindRequest = twixMessage.getBindRequest();

        // Twix : int version -> Snickers : boolean isVersion3
        snickersMessage.setVersion3( bindRequest.isLdapV3() );

        // Twix : LdapDN name -> Snickers : LdapDN name
        snickersMessage.setName( bindRequest.getName() );

        // Twix : Asn1Object authentication instanceOf SimpleAuthentication ->
        // Snickers : boolean isSimple
        // Twix : SimpleAuthentication OctetString simple -> Snickers : byte []
        // credentials
        Asn1Object authentication = bindRequest.getAuthentication();

        if ( authentication instanceof SimpleAuthentication )
        {
            snickersMessage.setSimple( true );
            snickersMessage.setCredentials( ( ( SimpleAuthentication ) authentication ).getSimple() );
        }
        else
        {
            snickersMessage.setSimple( false );
            snickersMessage.setCredentials( ( ( SaslCredentials ) authentication ).getCredentials() );
            snickersMessage.setSaslMechanism( ( ( SaslCredentials ) authentication ).getMechanism() );
        }

        return snickersMessage;
    }


    /**
     * Transform a CompareRequest message from a TwixMessage to a
     * SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers CompareRequestImpl
     */
    private Message transformCompareRequest( LdapMessage twixMessage, int messageId )
    {
        CompareRequestImpl snickersMessage = new CompareRequestImpl( messageId );
        CompareRequest compareRequest = twixMessage.getCompareRequest();

        // Twix : LdapDN entry -> Snickers : private LdapDN
        snickersMessage.setName( compareRequest.getEntry() );

        // Twix : LdapString attributeDesc -> Snickers : String attrId
        snickersMessage.setAttributeId( compareRequest.getAttributeDesc() );

        // Twix : OctetString assertionValue -> Snickers : byte[] attrVal
        if ( compareRequest.getAssertionValue() instanceof String )
        {
            snickersMessage.setAssertionValue( ( String ) compareRequest.getAssertionValue() );
        }
        else
        {
            snickersMessage.setAssertionValue( ( byte[] ) compareRequest.getAssertionValue() );
        }

        return snickersMessage;
    }


    /**
     * Transform a DelRequest message from a TwixMessage to a SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers DeleteRequestImpl
     */
    private Message transformDelRequest( LdapMessage twixMessage, int messageId )
    {
        DeleteRequestImpl snickersMessage = new DeleteRequestImpl( messageId );
        DelRequest delRequest = twixMessage.getDelRequest();

        // Twix : LdapDN entry -> Snickers : LdapDN
        snickersMessage.setName( delRequest.getEntry() );

        return snickersMessage;
    }


    /**
     * Transform an ExtendedRequest message from a TwixMessage to a
     * SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers ExtendedRequestImpl
     */
    private Message transformExtendedRequest( LdapMessage twixMessage, int messageId )
    {
        ExtendedRequest extendedRequest = twixMessage.getExtendedRequest();
        ExtendedRequestImpl snickersMessage = null;

        if ( extendedRequest.getRequestName().equals( GracefulShutdownRequest.EXTENSION_OID ) )
        {
            snickersMessage = new GracefulShutdownRequest( messageId );
        }
        else
        {
            snickersMessage = new ExtendedRequestImpl( messageId );
        }

        // Twix : OID requestName -> Snickers : String oid
        snickersMessage.setOid( extendedRequest.getRequestName() );

        // Twix : OctetString requestValue -> Snickers : byte [] payload
        snickersMessage.setPayload( extendedRequest.getRequestValue() );

        return snickersMessage;
    }


    /**
     * Transform a ModifyDNRequest message from a TwixMessage to a
     * SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers ModifyDNRequestImpl
     */
    private Message transformModifyDNRequest( LdapMessage twixMessage, int messageId )
    {
        ModifyDnRequestImpl snickersMessage = new ModifyDnRequestImpl( messageId );
        ModifyDNRequest modifyDNRequest = twixMessage.getModifyDNRequest();

        // Twix : LdapDN entry -> Snickers : LdapDN m_name
        snickersMessage.setName( modifyDNRequest.getEntry() );

        // Twix : RelativeLdapDN newRDN -> Snickers : LdapDN m_newRdn
        snickersMessage.setNewRdn( modifyDNRequest.getNewRDN() );

        // Twix : boolean deleteOldRDN -> Snickers : boolean m_deleteOldRdn
        snickersMessage.setDeleteOldRdn( modifyDNRequest.isDeleteOldRDN() );

        // Twix : LdapDN newSuperior -> Snickers : LdapDN m_newSuperior
        snickersMessage.setNewSuperior( modifyDNRequest.getNewSuperior() );

        return snickersMessage;
    }


    /**
     * Transform a ModifyRequest message from a TwixMessage to a SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers ModifyRequestImpl
     */
    private Message transformModifyRequest( LdapMessage twixMessage, int messageId )
    {
        ModifyRequestImpl snickersMessage = new ModifyRequestImpl( messageId );
        ModifyRequest modifyRequest = twixMessage.getModifyRequest();

        // Twix : LdapDN object -> Snickers : String name
        snickersMessage.setName( modifyRequest.getObject() );

        // Twix : ArrayList modifications -> Snickers : ArrayList mods
        /*if ( modifyRequest.getModifications() != null )
        {
            Iterator modifications = modifyRequest.getModifications().iterator();

            // Loop through the modifications
            while ( modifications.hasNext() )
            {
                snickersMessage.addModification( ( ModificationItemImpl ) modifications.next() );
            }
        }*/
        
        snickersMessage.setLdapMods(modifyRequest.getMods());

        return snickersMessage;
    }


    /**
     * Transform the Filter part of a SearchRequest to en ExprNode
     * 
     * @param twixFilter The filter to be transformed
     * @return An ExprNode
     */
    /*private ExprNode transformFilter( Filter twixFilter )
    {
        if ( twixFilter != null )
        {
            // Transform OR, AND or NOT leaves
            if ( twixFilter instanceof ConnectorFilter )
            {
                BranchNode branch = null;

                if ( twixFilter instanceof AndFilter )
                {
                    branch = new BranchNode( AssertionEnum.AND );
                }
                else if ( twixFilter instanceof OrFilter )
                {
                    branch = new BranchNode( AssertionEnum.OR );
                }
                else if ( twixFilter instanceof NotFilter )
                {
                    branch = new BranchNode( AssertionEnum.NOT );
                }

                List<Filter> filtersSet = ( ( ConnectorFilter ) twixFilter ).getFilterSet();

                // Loop on all AND/OR children
                if ( filtersSet != null )
                {
                    Iterator filters = filtersSet.iterator();

                    while ( filters.hasNext() )
                    {
                        branch.addNode( transformFilter( ( Filter ) filters.next() ) );
                    }
                }

                return branch;
            }
            else
            {
                // Transform PRESENT or ATTRIBUTE_VALUE_ASSERTION
                LeafNode branch = null;

                if ( twixFilter instanceof PresentFilter )
                {
                    branch = new PresenceNode( ( ( PresentFilter ) twixFilter ).getAttributeDescription() );
                }
                else if ( twixFilter instanceof AttributeValueAssertionFilter )
                {
                    AttributeValueAssertion ava = ( ( AttributeValueAssertionFilter ) twixFilter ).getAssertion();

                    // Transform =, >=, <=, ~= filters
                    switch ( ( ( AttributeValueAssertionFilter ) twixFilter ).getFilterType() )
                    {
                        case LdapConstants.EQUALITY_MATCH_FILTER:
                            if ( ava.getAssertionValue() instanceof String )
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(), 
                                    (String)ava.getAssertionValue(), 
                                    AssertionEnum.EQUALITY );
                            }
                            else
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(), 
                                    (byte[])ava.getAssertionValue(), 
                                    AssertionEnum.EQUALITY );
                            }
                            
                            break;

                        case LdapConstants.GREATER_OR_EQUAL_FILTER:
                            if ( ava.getAssertionValue() instanceof String )
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(),
                                    (String)ava.getAssertionValue(),
                                    AssertionEnum.GREATEREQ );
                            }
                            else
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(),
                                    (byte[])ava.getAssertionValue(),
                                    AssertionEnum.GREATEREQ );
                            }

                            break;

                        case LdapConstants.LESS_OR_EQUAL_FILTER:
                            if ( ava.getAssertionValue() instanceof String )
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(), 
                                    (String)ava.getAssertionValue(), 
                                    AssertionEnum.LESSEQ );
                            }
                            else
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(), 
                                    (byte[])ava.getAssertionValue(), 
                                    AssertionEnum.LESSEQ );
                            }

                            break;

                        case LdapConstants.APPROX_MATCH_FILTER:
                            if ( ava.getAssertionValue() instanceof String )
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(), 
                                    (String)ava.getAssertionValue(), 
                                    AssertionEnum.APPROXIMATE );
                            }
                            else
                            {
                                branch = new SimpleNode( ava.getAttributeDesc(), 
                                    (byte[])ava.getAssertionValue(), 
                                    AssertionEnum.APPROXIMATE );
                            }

                            break;
                    }

                }
                else if ( twixFilter instanceof SubstringFilter )
                {
                    // Transform Substring filters
                    SubstringFilter filter = ( SubstringFilter ) twixFilter;
                    String initialString = null;
                    String finalString = null;
                    List<String> anyString = null;

                    if ( filter.getInitialSubstrings() != null )
                    {
                        initialString = filter.getInitialSubstrings();
                    }

                    if ( filter.getFinalSubstrings() != null )
                    {
                        finalString = filter.getFinalSubstrings();
                    }

                    if ( filter.getAnySubstrings() != null )
                    {
                        anyString = new ArrayList<String>();

                        for ( String any:filter.getAnySubstrings() )
                        {
                            anyString.add( any );
                        }
                    }

                    branch = new SubstringNode( anyString, filter.getType(), initialString, finalString );
                }
                else if ( twixFilter instanceof ExtensibleMatchFilter )
                {
                    // Transform Extensible Match Filter
                    ExtensibleMatchFilter filter = ( ExtensibleMatchFilter ) twixFilter;
                    String attribute = null;
                    String matchingRule = null;

                    if ( filter.getType() != null )
                    {
                        attribute = filter.getType();
                    }

                    Object value = filter.getMatchValue();

                    if ( filter.getMatchingRule() != null )
                    {
                        matchingRule = filter.getMatchingRule();
                    }

                    if ( value instanceof String )
                    {
                        branch = new ExtensibleNode( attribute, (String)value, matchingRule, filter.isDnAttributes() );
                    }
                    else
                    {
                        if ( value != null )
                        {
                            branch = new ExtensibleNode( attribute, (byte[])value, matchingRule, filter.isDnAttributes() );
                        }
                        else
                        {
                            branch = new ExtensibleNode( attribute, (byte[])null, matchingRule, filter.isDnAttributes() );
                        }
                    }
                }

                return branch;
            }
        }
        else
        {
            // We have found nothing to transform. Return null then.
            return null;
        }
    }
*/

    /**
     * Transform a SearchRequest message from a TwixMessage to a SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers SearchRequestImpl
     */
    private Message transformSearchRequest( LdapMessage twixMessage, int messageId )
    {
        SearchRequestImpl snickersMessage = new SearchRequestImpl( messageId );
        SearchRequest searchRequest = twixMessage.getSearchRequest();

        // Twix : LdapDN baseObject -> Snickers : String baseDn
        snickersMessage.setBase( searchRequest.getBaseObject() );

        // Twix : int scope -> Snickers : ScopeEnum scope
        snickersMessage.setScope( searchRequest.getScope() );

        // Twix : int derefAliases -> Snickers : DerefAliasesEnum derefAliases
        switch ( searchRequest.getDerefAliases() )
        {
            case LdapConstants.DEREF_ALWAYS:
                snickersMessage.setDerefAliases( DerefAliasesEnum.DEREF_ALWAYS );
                break;

            case LdapConstants.DEREF_FINDING_BASE_OBJ:
                snickersMessage.setDerefAliases( DerefAliasesEnum.DEREF_FINDING_BASE_OBJ );
                break;

            case LdapConstants.DEREF_IN_SEARCHING:
                snickersMessage.setDerefAliases( DerefAliasesEnum.DEREF_IN_SEARCHING );
                break;

            case LdapConstants.NEVER_DEREF_ALIASES:
                snickersMessage.setDerefAliases( DerefAliasesEnum.NEVER_DEREF_ALIASES );
                break;
        }

        // Twix : int sizeLimit -> Snickers : int sizeLimit
        snickersMessage.setSizeLimit( searchRequest.getSizeLimit() );

        // Twix : int timeLimit -> Snickers : int timeLimit
        snickersMessage.setTimeLimit( searchRequest.getTimeLimit() );

        // Twix : boolean typesOnly -> Snickers : boolean typesOnly
        snickersMessage.setTypesOnly( searchRequest.isTypesOnly() );

        // Twix : Filter filter -> Snickers : ExprNode filter
        Filter twixFilter = searchRequest.getFilter();

        snickersMessage.setFilter( twixFilter  );

        // Twix : ArrayList attributes -> Snickers : ArrayList attributes
        if ( searchRequest.getAttributes() != null )
        {
        	
        	
        	Iterator<net.sourceforge.myvd.types.Attribute> attributes = searchRequest.getAttributes().iterator();

            if ( attributes != null )
            {
                while ( attributes.hasNext() )
                {
                    Attribute attribute = attributes.next();

                    if ( attribute != null )
                    {
                        snickersMessage.addAttribute( attribute.getAttribute().getName() );
                    }
                }
            }
        }

        return snickersMessage;
    }


    /**
     * Transform an UnBindRequest message from a TwixMessage to a
     * SnickersMessage
     * 
     * @param twixMessage The message to transform
     * @param messageId The message Id
     * @return A Snickers UnBindRequestImpl
     */
    private Message transformUnBindRequest( LdapMessage twixMessage, int messageId )
    {
        return new UnbindRequestImpl( messageId );
    }


    /**
     * Transform the Twix message to a codec neutral message.
     * 
     * @param obj the object to transform
     * @return the object transformed
     */
    public Message transform( Object obj )
    {
        LdapMessage twixMessage = ( LdapMessage ) obj;
        int messageId = twixMessage.getMessageId();

        if ( IS_DEBUG )
        {
            log.debug( "Transforming LdapMessage <" + messageId + ", " + twixMessage.getMessageTypeName()
                + "> from Twix to Snickers." );
        }

        Message snickersMessage = null;

        int messageType = twixMessage.getMessageType();

        switch ( messageType )
        {
            case ( LdapConstants.BIND_REQUEST  ):
                snickersMessage = transformBindRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.UNBIND_REQUEST  ):
                snickersMessage = transformUnBindRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.SEARCH_REQUEST  ):
                snickersMessage = transformSearchRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.MODIFY_REQUEST  ):
                snickersMessage = transformModifyRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.ADD_REQUEST  ):
                snickersMessage = transformAddRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.DEL_REQUEST  ):
                snickersMessage = transformDelRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.MODIFYDN_REQUEST  ):
                snickersMessage = transformModifyDNRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.COMPARE_REQUEST  ):
                snickersMessage = transformCompareRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.ABANDON_REQUEST  ):
                snickersMessage = transformAbandonRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.EXTENDED_REQUEST  ):
                snickersMessage = transformExtendedRequest( twixMessage, messageId );
                break;

            case ( LdapConstants.BIND_RESPONSE  ):
            case ( LdapConstants.SEARCH_RESULT_ENTRY  ):
            case ( LdapConstants.SEARCH_RESULT_DONE  ):
            case ( LdapConstants.SEARCH_RESULT_REFERENCE  ):
            case ( LdapConstants.MODIFY_RESPONSE  ):
            case ( LdapConstants.ADD_RESPONSE  ):
            case ( LdapConstants.DEL_RESPONSE  ):
            case ( LdapConstants.MODIFYDN_RESPONSE  ):
            case ( LdapConstants.COMPARE_RESPONSE  ):
            case ( LdapConstants.EXTENDED_RESPONSE  ):
                // Nothing to do !
                break;

            default:
                throw new IllegalStateException( "shouldn't happen - if it does then we have issues" );
        }

        // Transform the controls, too
        List twixControls = twixMessage.getControls();

        if ( twixControls != null )
        {
            Iterator controls = twixControls.iterator();

            while ( controls.hasNext() )
            {
                ControlImpl neutralControl = null;
                net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.Control twixControl = ( net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.Control ) controls
                    .next();

                if ( twixControl.getControlValue() instanceof PSearchControl )
                {
                    PersistentSearchControl neutralPsearch = new PersistentSearchControl();
                    neutralControl = neutralPsearch;
                    PSearchControl twixPsearch = ( PSearchControl ) twixControl.getControlValue();
                    neutralPsearch.setChangeTypes( twixPsearch.getChangeTypes() );
                    neutralPsearch.setChangesOnly( twixPsearch.isChangesOnly() );
                    neutralPsearch.setReturnECs( twixPsearch.isReturnECs() );
                    neutralPsearch.setCritical( twixControl.getCriticality() );
                    neutralPsearch.setValue( twixControl.getEncodedValue() );
                }
                else if ( twixControl.getControlValue() instanceof SubEntryControl )
                {
                    SubentriesControl neutralSubentriesControl = new SubentriesControl();
                    SubEntryControl twixSubentriesControl = ( SubEntryControl ) twixControl.getControlValue();
                    neutralControl = neutralSubentriesControl;
                    neutralSubentriesControl.setVisibility( twixSubentriesControl.isVisible() );
                    neutralSubentriesControl.setCritical( twixControl.getCriticality() );
                    neutralSubentriesControl.setValue( twixControl.getEncodedValue() );
                }
                else if ( twixControl.getControlValue() instanceof byte[] )
                {
                    neutralControl = new ControlImpl()
                    {
                        // Just to avoid a compilation warning !!!
                        public static final long serialVersionUID = 1L;


                        public byte[] getEncodedValue()
                        {
                            return null;
                        }
                    };

                    // Twix : boolean criticality -> Snickers : boolean
                    // m_isCritical
                    neutralControl.setCritical( twixControl.getCriticality() );

                    // Twix : OID controlType -> Snickers : String m_oid
                    neutralControl.setType( twixControl.getControlType() );

                    // Twix : OctetString controlValue -> Snickers : byte []
                    // m_value
                    neutralControl.setValue( ( byte[] ) twixControl.getControlValue() );
                }
                else if ( twixControl.getControlValue() == null )
                {
                    neutralControl = new ControlImpl()
                    {
                        // Just to avoid a compilation warning !!!
                        public static final long serialVersionUID = 1L;


                        public byte[] getEncodedValue()
                        {
                            return null;
                        }
                    };

                    // Twix : boolean criticality -> Snickers : boolean
                    // m_isCritical
                    neutralControl.setCritical( twixControl.getCriticality() );

                    // Twix : OID controlType -> Snickers : String m_oid
                    neutralControl.setType( twixControl.getControlType() );

                    // Twix : OctetString controlValue -> Snickers : byte []
                    // m_value
                    neutralControl.setValue( ( byte[] ) twixControl.getControlValue() );
                }
                

                snickersMessage.add( neutralControl );
            }
        }

        return snickersMessage;
    }


    /**
     * Transform a Ldapresult part of a Snickers Response to a Twix LdapResult
     * 
     * @param snickersLdapResult The Snickers LdapResult to transform
     * @return A Twix LdapResult
     */
    private LdapResult transformLdapResult( LdapResultImpl snickersLdapResult )
    {
        LdapResult twixLdapResult = new LdapResult();

        // Snickers : ResultCodeEnum resultCode -> Twix : int resultCode
        twixLdapResult.setResultCode( snickersLdapResult.getResultCode() );

        // Snickers : String errorMessage -> Twix : LdapString errorMessage
        String errorMessage = snickersLdapResult.getErrorMessage();

        if ( ( errorMessage == null ) || ( errorMessage.length() == 0 ) )
        {
            twixLdapResult.setErrorMessage( "" );
        }
        else
        {
            twixLdapResult.setErrorMessage( new String( snickersLdapResult.getErrorMessage().getBytes() ) );
        }

        // Snickers : String matchedDn -> Twix : LdapDN matchedDN
        twixLdapResult.setMatchedDN( snickersLdapResult.getMatchedDn() );

        // Snickers : Referral referral -> Twix : ArrayList referrals
        ReferralImpl snisckersReferrals = ( ReferralImpl ) snickersLdapResult.getReferral();

        if ( snisckersReferrals != null )
        {
            Iterator referrals = snisckersReferrals.getLdapUrls().iterator();
            twixLdapResult.initReferrals();

            while ( referrals.hasNext() )
            {
                String referral = ( String ) referrals.next();

                try
                {
                    LdapURL ldapUrl = new LdapURL( referral.getBytes() );
                    twixLdapResult.addReferral( ldapUrl );
                }
                catch ( LdapURLEncodingException lude )
                {
                    log.warn( "The referral " + referral + " is invalid : " + lude.getMessage() );
                    twixLdapResult.addReferral( LdapURL.EMPTY_URL );
                }
            }
        }

        return twixLdapResult;
    }


    /**
     * Transform a Snickers AddResponse to a Twix AddResponse
     * 
     * @param twixMessage The Twix AddResponse to produce
     * @param snickersMessage The incoming Snickers AddResponse
     */
    private void transformAddResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        AddResponseImpl snickersAddResponse = ( AddResponseImpl ) snickersMessage;

        AddResponse addResponse = new AddResponse();

        // Transform the ldapResult
        addResponse.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersAddResponse.getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( addResponse );
    }


    /**
     * Transform a Snickers BindResponse to a Twix BindResponse
     * 
     * @param twixMessage The Twix BindResponse to produce
     * @param snickersMessage The incoming Snickers BindResponse
     */
    private void transformBindResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        BindResponseImpl snickersBindResponse = ( BindResponseImpl ) snickersMessage;

        BindResponse bindResponse = new BindResponse();

        // Snickers : byte [] serverSaslCreds -> Twix : OctetString
        // serverSaslCreds
        byte[] serverSaslCreds = snickersBindResponse.getServerSaslCreds();

        if ( serverSaslCreds != null )
        {
            bindResponse.setServerSaslCreds( serverSaslCreds );
        }

        // Transform the ldapResult
        bindResponse.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersBindResponse.getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( bindResponse );
    }


    /**
     * Transform a Snickers CompareResponse to a Twix CompareResponse
     * 
     * @param twixMessage The Twix CompareResponse to produce
     * @param snickersMessage The incoming Snickers CompareResponse
     */
    private void transformCompareResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        CompareResponseImpl snickersCompareResponse = ( CompareResponseImpl ) snickersMessage;

        CompareResponse compareResponse = new CompareResponse();

        // Transform the ldapResult
        compareResponse
            .setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersCompareResponse.getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( compareResponse );
    }


    /**
     * Transform a Snickers DelResponse to a Twix DelResponse
     * 
     * @param twixMessage The Twix DelResponse to produce
     * @param snickersMessage The incoming Snickers DelResponse
     */
    private void transformDelResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        DeleteResponseImpl snickersDelResponse = ( DeleteResponseImpl ) snickersMessage;

        DelResponse delResponse = new DelResponse();

        // Transform the ldapResult
        delResponse.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersDelResponse.getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( delResponse );
    }


    /**
     * Transform a Snickers ExtendedResponse to a Twix ExtendedResponse
     * 
     * @param twixMessage The Twix ExtendedResponse to produce
     * @param snickersMessage The incoming Snickers ExtendedResponse
     */
    private void transformExtendedResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        ExtendedResponseImpl snickersExtendedResponse = ( ExtendedResponseImpl ) snickersMessage;
        ExtendedResponse extendedResponse = new ExtendedResponse();

        // Snickers : String oid -> Twix : OID responseName
        try
        {
            extendedResponse.setResponseName( new OID( snickersExtendedResponse.getResponseName() ) );
        }
        catch ( DecoderException de )
        {
            log.warn( "The OID " + snickersExtendedResponse.getResponseName() + " is invalid : " + de.getMessage() );
            extendedResponse.setResponseName( null );
        }

        // Snickers : byte [] value -> Twix : Object response
        extendedResponse.setResponse( snickersExtendedResponse.getResponse() );

        // Transform the ldapResult
        extendedResponse.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersExtendedResponse
            .getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( extendedResponse );
    }


    /**
     * Transform a Snickers ModifyResponse to a Twix ModifyResponse
     * 
     * @param twixMessage The Twix ModifyResponse to produce
     * @param snickersMessage The incoming Snickers ModifyResponse
     */
    private void transformModifyResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        ModifyResponseImpl snickersModifyResponse = ( ModifyResponseImpl ) snickersMessage;

        ModifyResponse modifyResponse = new ModifyResponse();

        // Transform the ldapResult
        modifyResponse.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersModifyResponse.getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( modifyResponse );
    }


    /**
     * Transform a Snickers ModifyDNResponse to a Twix ModifyDNResponse
     * 
     * @param twixMessage The Twix ModifyDNResponse to produce
     * @param snickersMessage The incoming Snickers ModifyDNResponse
     */
    private void transformModifyDNResponse( LdapMessage twixMessage, Message snickersMessage )
    {
        ModifyDnResponseImpl snickersModifyDNResponse = ( ModifyDnResponseImpl ) snickersMessage;

        ModifyDNResponse modifyDNResponse = new ModifyDNResponse();

        // Transform the ldapResult
        modifyDNResponse.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersModifyDNResponse
            .getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( modifyDNResponse );
    }


    /**
     * Transform a Snickers SearchResponseDone to a Twix SearchResultDone
     * 
     * @param twixMessage The Twix SearchResultDone to produce
     * @param snickersMessage The incoming Snickers SearchResponseDone
     */
    private void transformSearchResultDone( LdapMessage twixMessage, Message snickersMessage )
    {
        SearchResponseDoneImpl snickersSearchResponseDone = ( SearchResponseDoneImpl ) snickersMessage;
        SearchResultDone searchResultDone = new SearchResultDone();

        // Transform the ldapResult
        searchResultDone.setLdapResult( transformLdapResult( ( LdapResultImpl ) snickersSearchResponseDone
            .getLdapResult() ) );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( searchResultDone );
    }


    /**
     * Transform a Snickers SearchResponseEntry to a Twix SearchResultEntry
     * 
     * @param twixMessage The Twix SearchResultEntry to produce
     * @param snickersMessage The incoming Snickers SearchResponseEntry
     */
    private void transformSearchResultEntry( LdapMessage twixMessage, Message snickersMessage )
    {
        SearchResponseEntry snickersSearchResultResponse = ( SearchResponseEntry ) snickersMessage;
        SearchResultEntry searchResultEntry = new SearchResultEntry();

        // Snickers : LdapDN dn -> Twix : LdapDN objectName
        searchResultEntry.setObjectName( snickersSearchResultResponse.getObjectName() );

        // Snickers : Attributes attributes -> Twix : ArrayList
        // partialAttributeList
        searchResultEntry.setPartialAttributeList( snickersSearchResultResponse.getLDAPAttributeSet() );

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( searchResultEntry );
    }


    /**
     * Transform a Snickers SearchResponseReference to a Twix
     * SearchResultReference
     * 
     * @param twixMessage The Twix SearchResultReference to produce
     * @param snickersMessage The incoming Snickers SearchResponseReference
     */
    private void transformSearchResultReference( LdapMessage twixMessage, Message snickersMessage )
    {
        SearchResponseReferenceImpl snickersSearchResponseReference = ( SearchResponseReferenceImpl ) snickersMessage;
        SearchResultReference searchResultReference = new SearchResultReference();

        // Snickers : Referral m_referral -> Twix: ArrayList
        // searchResultReferences
        Referral referrals = snickersSearchResponseReference.getReferral();

        // Loop on all referals
        if ( referrals != null )
        {
            Collection urls = referrals.getLdapUrls();

            if ( urls != null )
            {
                Iterator url = urls.iterator();

                while ( url.hasNext() )
                {
                    String urlValue = ( String ) url.next();

                    try
                    {
                        searchResultReference.addSearchResultReference( new LdapURL( urlValue ) );
                    }
                    catch ( LdapURLEncodingException luee )
                    {
                        log.warn( "The LdapURL " + urlValue + " is incorrect : " + luee.getMessage() );
                    }
                }
            }
        }

        // Set the operation into the LdapMessage
        twixMessage.setProtocolOP( searchResultReference );
    }


    /**
     * Transform the Snickers message to a Twix message.
     * 
     * @param msg the message to transform
     * @return the msg transformed
     */
    public Object transform( Message msg )
    {
        if ( IS_DEBUG )
        {
            log.debug( "Transforming message type " + msg.getType() );
        }

        LdapMessage twixMessage = new LdapMessage();

        twixMessage.setMessageId( msg.getMessageId() );

        switch ( msg.getType() )
        {
            case SEARCH_RES_ENTRY :
                transformSearchResultEntry( twixMessage, msg );
                break;
                
            case SEARCH_RES_DONE :
                transformSearchResultDone( twixMessage, msg );
                break;
                
            case SEARCH_RES_REF :
                transformSearchResultReference( twixMessage, msg );
                break;
                
            case BIND_RESPONSE :
                transformBindResponse( twixMessage, msg );
                break;
                
            case ADD_RESPONSE :
                transformAddResponse( twixMessage, msg );
                break;
                
            case COMPARE_RESPONSE :
                transformCompareResponse( twixMessage, msg );
                break;
                
            case DEL_RESPONSE :
                transformDelResponse( twixMessage, msg );
                break;
         
            case MODIFY_RESPONSE :
                transformModifyResponse( twixMessage, msg );
                break;

            case MOD_DN_RESPONSE :
                transformModifyDNResponse( twixMessage, msg );
                break;
                
            case EXTENDED_RESP :
                transformExtendedResponse( twixMessage, msg );
                break;
                
        }

        // We also have to transform the controls...
        if ( !msg.getControls().isEmpty() )
        {
            transformControls( twixMessage, msg );
        }

        if ( IS_DEBUG )
        {
            log.debug( "Transformed message : " + twixMessage );
        }

        return twixMessage;
    }

    /**
     * Transforms the controls
     * @param twixMessage The Twix SearchResultReference to produce
     * @param msg The incoming Snickers SearchResponseReference
     */
    private void transformControls( LdapMessage twixMessage, Message msg )
    {
        Iterator list = msg.getControls().values().iterator();
        
        while ( list.hasNext() )
        {
            javax.naming.ldap.Control control = ( javax.naming.ldap.Control ) list.next();
            net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.Control twixControl = new net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.Control();
            twixMessage.addControl( twixControl );
            twixControl.setCriticality( control.isCritical() );
            twixControl.setControlValue( control.getEncodedValue() );
            twixControl.setEncodedValue( control.getEncodedValue() );
            twixControl.setControlType( new String( Asn1StringUtils.getBytesUtf8( control.getID() ) ) );
            twixControl.setParent( twixMessage );
        }
    }
}
