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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.Asn1Object;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ScopeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;

import java.io.UnsupportedEncodingException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;



import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.IAsn1Container;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.UniversalTag;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.Value;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;


/**
 * A SearchRequest ldapObject. It's a sub-class of Asn1Object, and it implements
 * the ldapObject class to be seen as a member of the LdapMessage CHOICE.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchRequest extends LdapMessage
{
    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The base DN */
    private LdapDN baseObject;

    /** The scope. It could be baseObject, singleLevel or wholeSubtree. */
    private ScopeEnum scope;

    /**
     * The deref alias could be neverDerefAliases, derefInSearching,
     * derefFindingBaseObj or derefAlways.
     */
    private int derefAliases;

    /** The size limit (number of objects returned) */
    private int sizeLimit;

    /**
     * The time limit (max time to process the response before returning the
     * result)
     */
    private int timeLimit;

    /**
     * An indicator as to whether search results will contain both attribute
     * types and values, or just attribute types. Setting this field to TRUE
     * causes only attribute types (no values) to be returned. Setting this
     * field to FALSE causes both attribute types and values to be returned.
     */
    private boolean typesOnly;

    /** The filter tree */
    private Filter filter;
    
    
    /** The current filter. This is used while decoding a PDU */
    private FilterNode currentFilter;

    /** A temporary storage for a terminal Filter */
    private FilterNode terminalFilter;
    
    /** The searchRequest length */
    private int searchRequestLength;

    /** The attributeDescriptionList length */
    private int attributeDescriptionListLength;


    private ArrayList<net.sourceforge.myvd.types.Attribute> attribs;
    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new SearchRequest object.
     */
    public SearchRequest()
    {
        super();
        this.attribs = new ArrayList<Attribute>();
    }


    // ~ Methods
    // ------------------------------------------------------------------------------------

    /**
     * Get the message type
     * 
     * @return Returns the type.
     */
    public int getMessageType()
    {
        return LdapConstants.SEARCH_REQUEST;
    }


    /**
     * Get the list of attributes
     * 
     * @return Returns the attributes.
     */
    public ArrayList<net.sourceforge.myvd.types.Attribute> getAttributes()
    {
        return attribs;
    }


    /**
     * Add an attribute to the attributes list.
     * 
     * @param attribute The attribute to add to the list
     */
    public void addAttribute( String attribute )
    {
        attribs.add(new Attribute(attribute));
    }


    /**
     * Get the base object
     * 
     * @return Returns the baseObject.
     */
    public LdapDN getBaseObject()
    {
        return baseObject;
    }


    /**
     * Set the base object
     * 
     * @param baseObject The baseObject to set.
     */
    public void setBaseObject( LdapDN baseObject )
    {
        this.baseObject = baseObject;
    }


    /**
     * Get the derefAliases flag
     * 
     * @return Returns the derefAliases.
     */
    public int getDerefAliases()
    {
        return derefAliases;
    }


    /**
     * Set the derefAliases flag
     * 
     * @param derefAliases The derefAliases to set.
     */
    public void setDerefAliases( int derefAliases )
    {
        this.derefAliases = derefAliases;
    }


    /**
     * Get the filter
     * 
     * @return Returns the filter.
     */
    public Filter getFilter()
    {
        return filter;
    }


    /**
     * Set the filter
     * 
     * @param filter The filter to set.
     */
    public void setFilter( Filter filter )
    {
        this.filter = filter;
    }


    /**
     * Get the search scope
     * 
     * @return Returns the scope.
     */
    public ScopeEnum getScope()
    {
        return scope;
    }


    /**
     * Set the search scope
     * 
     * @param scope The scope to set.
     */
    public void setScope( ScopeEnum scope )
    {
        this.scope = scope;
    }


    /**
     * Get the size limit
     * 
     * @return Returns the sizeLimit.
     */
    public int getSizeLimit()
    {
        return sizeLimit;
    }


    /**
     * Set the size limit
     * 
     * @param sizeLimit The sizeLimit to set.
     */
    public void setSizeLimit( int sizeLimit )
    {
        this.sizeLimit = sizeLimit;
    }


    /**
     * Get the time limit
     * 
     * @return Returns the timeLimit.
     */
    public int getTimeLimit()
    {
        return timeLimit;
    }


    /**
     * Set the time limit
     * 
     * @param timeLimit The timeLimit to set.
     */
    public void setTimeLimit( int timeLimit )
    {
        this.timeLimit = timeLimit;
    }


    /**
     * Get the typesOnly flag
     * 
     * @return Returns the typesOnly.
     */
    public boolean isTypesOnly()
    {
        return typesOnly;
    }


    /**
     * Set the typesOnly flag
     * 
     * @param typesOnly The typesOnly to set.
     */
    public void setTypesOnly( boolean typesOnly )
    {
        this.typesOnly = typesOnly;
    }


    /**
     * Get the current dilter
     * 
     * @return Returns the currentFilter.
     */
    public FilterNode getCurrentFilter()
    {
        return currentFilter;
    }

    /**
     * Get the comparison dilter
     * 
     * @return Returns the comparisonFilter.
     */
    public FilterNode getTerminalFilter()
    {
        return terminalFilter;
    }

    /**
     * Set the terminal filter
     * 
     * @param terminalFilter the teminalFilter.
     */
    public void setTerminalFilter( FilterNode terminalFilter )
    {
        this.terminalFilter = terminalFilter;
    }


    /**
     * Add a current filter. We have two cases :
     * - there is no previous current filter : the filter
     * is the top level filter
     * - there is a previous current filter : the filter is added 
     * to the currentFilter set, and the current filter is changed
     * 
     * In any case, the previous current filter will always be a
     * ConnectorFilter when this method is called.
     * 
     * @param filter The filter to set.
     */
    public void addCurrentFilter( FilterNode localFilter ) throws DecoderException
    {
        if ( currentFilter != null )
        {
            // Ok, we have a parent. The new Filter will be added to
            // this parent, and will become the currentFilter if it's a connector.
            //( ( ConnectorFilter ) currentFilter ).addFilter( localFilter );
            //localFilter.setParent( currentFilter );
        	
        	this.currentFilter.addNode(localFilter);
        	localFilter.setParent(currentFilter);
            
            
        	
        	FilterType filterType = localFilter.getType();
        	
        	switch (filterType) {
        	case AND:
        	case OR:
        	case NOT:
        		this.currentFilter = localFilter;
        		break;
        	
        	}
        	
        	
        	
        }
        else
        {
            // No parent. This Filter will become the root.
            currentFilter = localFilter;
            this.filter = new Filter(localFilter);
            this.currentFilter.setParent(null);
            
        }
    }

    /**
     * Set the current dilter
     * 
     * @param filter The filter to set.
     */
    public void setCurrentFilter( Filter filter )
    {
        this.filter = filter;
    }


    /**
     * This method is used to clear the filter's stack for terminated elements. An element
     * is considered as terminated either if :
     *  - it's a final element (ie an element which cannot contains a Filter)
     *  - its current length equals its expected length.
     * 
     * @param container The container being decoded
     */
    public void unstackFilters( IAsn1Container container )
    {
    	
    	FilterNode parent = this.terminalFilter.getParent();
    	
    	//a "not" should only have a single child
    	if (parent != null  && parent.getType() ==  FilterType.NOT) {
    		parent = parent.getParent();
    	}
    	
    	if (parent != null) {
    		this.currentFilter = parent;
    		this.terminalFilter = parent;
    	}
    	
    	/*currentFilter = filterParent;
        localFilter = currentFilter;
        localParent = localParent.getParent();*/
    	
    	
        /*LdapMessageContainer ldapMessageContainer = ( LdapMessageContainer ) container;

        TLV tlv = ldapMessageContainer.getCurrentTLV();
        TLV localParent = tlv.getParent();
        FilterNode localFilter = terminalFilter;

        // The parent has been completed, so fold it
        while ( ( localParent != null ) && ( localParent.getExpectedLength() == 0 ) )
        {
            if ( localParent.getTag() != 0 )
            {
                localParent = localParent.getParent();
                
            }
            else
            {
                //Asn1Object filterParent = localFilter.getParent();
                FilterNode filterParent = localFilter.getParent();
                // We have a special case with PresentFilter, which has not been 
                // pushed on the stack, so we need to get its parent's parent
                
                
                
                /*if ( localFilter instanceof Filter )
                {
                    filterParent = filterParent.getParent();
                }
                else if ( filterParent instanceof Filter )
                {
                    filterParent = filterParent.getParent();
                }
                
                
                
                
                
                
                
                if ( filterParent != null )
                {
                    // The parent is a filter ; it will become the new currentFilter
                    // and we will loop again. 
                    currentFilter = filterParent;
                    localFilter = currentFilter;
                    localParent = localParent.getParent();
                }
                else
                {
                    // We can stop the recursion, we have reached the searchResult Object
                    break;
                }
            }
        }*/
    }

    /**
     * Compute the SearchRequest length
     * 
     * SearchRequest :
     * 
     * 0x63 L1
     *  |
     *  +--> 0x04 L2 baseObject
     *  +--> 0x0A 0x01 scope
     *  +--> 0x0A 0x01 derefAliases
     *  +--> 0x02 0x0(1..4) sizeLimit
     *  +--> 0x02 0x0(1..4) timeLimit
     *  +--> 0x01 0x01 typesOnly
     *  +--> filter.computeLength()
     *  +--> 0x30 L3 (Attribute description list)
     *        |
     *        +--> 0x04 L4-1 Attribute description 
     *        +--> 0x04 L4-2 Attribute description 
     *        +--> ... 
     *        +--> 0x04 L4-i Attribute description 
     *        +--> ... 
     *        +--> 0x04 L4-n Attribute description 
     */
    public int computeLength()
    {
        return 0;
    }


    /**
     * Encode the SearchRequest message to a PDU.
     * 
     * SearchRequest :
     * 
     * 0x63 LL
     *   0x04 LL baseObject
     *   0x0A 01 scope
     *   0x0A 01 derefAliases
     *   0x02 0N sizeLimit
     *   0x02 0N timeLimit
     *   0x01 0x01 typesOnly
     *   filter.encode()
     *   0x30 LL attributeDescriptionList
     *     0x04 LL attributeDescription
     *     ... 
     *     0x04 LL attributeDescription
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
       return null;
    }


    /**
     * @return A string that represent the Filter
     */
    private String buildFilter()
    {
        if ( filter == null )
        {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        sb.append( "(" ).append( filter ).append( ")" );

        return sb.toString();
    }


    /**
     * @return A string that represent the atributes list
     */
    private String buildAttributes()
    {
        return "";
    }


    /**
     * Return a string the represent a SearchRequest
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer();

        sb.append( "    Search Request\n" );
        sb.append( "        Base Object : '" ).append( baseObject ).append( "'\n" );
        sb.append( "        Scope : " );

        switch ( scope )
        {
            case BASE_OBJECT:
                sb.append( "base object" );
                break;

            case SINGLE_LEVEL:
                sb.append( "single level" );
                break;

            case WHOLE_SUBTREE:
                sb.append( "whole subtree" );
                break;
        }

        sb.append( "\n" );

        sb.append( "        Deref Aliases : " );

        switch ( derefAliases )
        {
            case LdapConstants.NEVER_DEREF_ALIASES:
                sb.append( "never Deref Aliases" );
                break;

            case LdapConstants.DEREF_IN_SEARCHING:
                sb.append( "deref In Searching" );
                break;

            case LdapConstants.DEREF_FINDING_BASE_OBJ:
                sb.append( "deref Finding Base Obj" );
                break;

            case LdapConstants.DEREF_ALWAYS:
                sb.append( "deref Always" );
                break;
        }

        sb.append( "\n" );

        sb.append( "        Size Limit : " );

        if ( sizeLimit == 0 )
        {
            sb.append( "no limit" );
        }
        else
        {
            sb.append( sizeLimit );
        }

        sb.append( "\n" );

        sb.append( "        Time Limit : " );

        if ( timeLimit == 0 )
        {
            sb.append( "no limit" );
        }
        else
        {
            sb.append( timeLimit );
        }

        sb.append( "\n" );

        sb.append( "        Types Only : " ).append( typesOnly ).append( "\n" );
        sb.append( "        Filter : '" ).append( buildFilter() ).append( "'\n" );

        
        return sb.toString();
    }
}
