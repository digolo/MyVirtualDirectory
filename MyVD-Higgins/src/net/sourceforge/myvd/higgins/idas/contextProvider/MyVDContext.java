/**
 * Copyright (c) 2006 Novell, Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; version 2.1 of the license.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com
 * 
 * Changes Copyright (c) 2007 Marc Boorshtein
 */

package net.sourceforge.myvd.higgins.idas.contextProvider;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;


import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;


import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.higgins.idas.contextProvider.config.MyVDHigginsConfig;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.protocol.ldap.SearchResponseIterator;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.Filter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ExceptionUtils;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.types.*;
import openxdas.XDasEvents;
import openxdas.XDasException;
import openxdas.XDasOutcomes;
import openxdas.XDasRecord;
import openxdas.XDasSession;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.log4j.varia.NullAppender;
import org.bandit.util.misc.CIStringKey;
import org.bandit.util.misc.NonEscapedAttrXMLWriter;
import org.dom4j.dom.DOMDocument;
import org.dom4j.dom.DOMElement;
import org.dom4j.dtd.InternalEntityDecl;
import org.dom4j.tree.DefaultDocumentType;
import org.eclipse.higgins.idas.AuthNNamePasswordMaterials;
import org.eclipse.higgins.idas.ContextNotOpenException;
import org.eclipse.higgins.idas.ContextOpenException;
import org.eclipse.higgins.idas.IAttribute;
import org.eclipse.higgins.idas.IContext;
import org.eclipse.higgins.idas.IDigitalSubject;
import org.eclipse.higgins.idas.IFilter;
import org.eclipse.higgins.idas.IFilterPropertyAssertion;
import org.eclipse.higgins.idas.IMetadata;
import org.eclipse.higgins.idas.IPropertyValue;
import org.eclipse.higgins.idas.IRelationship;
import org.eclipse.higgins.idas.ISimpleValue;
import org.eclipse.higgins.idas.IdASException;
import org.eclipse.higgins.idas.NotImplementedException;
import org.eclipse.higgins.idas.impl.BasicFilter;
import org.eclipse.higgins.idas.impl.BasicFilterAssertion;
import org.eclipse.higgins.idas.impl.BasicFilterAttributeAssertion;
import org.eclipse.higgins.idas.impl.BasicMetadata;
import org.exolab.castor.xml.MarshalException;
import org.exolab.castor.xml.ValidationException;


import org.bandit.util.config.gen.Env;
import org.bandit.util.config.gen.Realm;
import org.bandit.util.config.gen.RealmTypeItem;
import org.bandit.util.config.gen.Realms;
import org.bandit.util.config.gen.RealmsType;
import org.bandit.util.config.gen.RealmsTypeItem;
import org.bandit.util.config.gen.types.ConnectorTypeType;
import org.bandit.util.config.gen.LDAPConnector;

import org.bandit.util.jndi.RfcFilter;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSchema;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPObjectClassSchema;
import com.novell.ldap.LDAPSchema;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSyntaxSchema;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

/**
*
* @author jimse@novell.com
* @author tdoman@novell.com
* @author dbuss@novell.com
* @author Marc Boorshtein, mboorshtein@gmail.com
*/

public class MyVDContext  implements IContext
{
	private Logger _log = Logger.getLogger(MyVDContext.class.getName());
	
	private Hashtable<String, Object> _env;	
	private HashSet<IMetadata> _metaData;
	private HashMap<CIStringKey, Vector<String>> _schemaAttrDomainHashMap;
	private HashMap<CIStringKey, String> _schemaAttrCaseHashMap;
	private HashMap<String, SyntaxMap> _syntaxHashMap;
	private HashMap<CIStringKey, Vector<String>> _attrInHashMap = new HashMap<CIStringKey, Vector<String>>();
	private HashMap<CIStringKey, String> _attrOutHashMap = new HashMap<CIStringKey, String>();
	private URI _contextRef;
	private boolean _bIsOpen = false;
	private static final String ATTR_DISAMBIGUATOR = "#attr_";
	private static final String DEFAULT_ATTR_TYPE_PREFIX = "http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap";
	private LDAPConnector _ldapConnector;
	private Realm _targetRealm;
	private XDasSession _xdasSession;
	
	String propsConfig;
	String searchBase;
	String uidAttrib;
	
	
	Insert[] globalChain;
	Router router;
	private Server server;

	private HashMap userSession;

	private class SyntaxMap
	{
		private String _label;
		private String _urlName;
		private String _owlType;

		SyntaxMap(
			String label,
			String owlType)
		{
			_label = label;
			_urlName = label.replaceAll(" ", "");
			_owlType = owlType;
		}

		public String getLabel()
		{
			return _label;
		}

		public String getURLName()
		{
			return "syntax_" + _urlName;
		}

		public String getOWLType()
		{
			return _owlType;
		}
	};

	/**
	 */
	public MyVDContext(
		Insert[] globalChain,Router router,URI contextRef,MyVDHigginsConfig cfg) throws IdASException
	{
		
		this._contextRef = contextRef;
		
		/*if (!Logger.getRootLogger().getAllAppenders().hasMoreElements())
			BasicConfigurator.configure(new NullAppender());
		_env = new Hashtable<String, Object>();*/
		_initSyntaxMap();
		_initAttrOutMap();
		_initAttrInMap();
		_initXDASSession();
		
		this.searchBase = cfg.getUserSearchBase();
		this.uidAttrib = cfg.getUserIdAttribute();

		this.router = router;
		this.globalChain = globalChain;
		

		
	}

	/**
	 */
	private void _initXDASSession() throws IdASException
	{
		try
		{
			_xdasSession = new XDasSession(_contextRef.toString(), null, null, null, null, null);
		}
		catch (XDasException e)
		{
			throw new IdASException(e);
		}
		catch (SocketException e)
		{
			//e.printStackTrace();
		}
		catch (IOException e)
		{
			//e.printStackTrace();
		}
	}

	/**
	 */
	private void _initSyntaxMap()
	{
		_syntaxHashMap = new HashMap<String, SyntaxMap>();

		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.3", new SyntaxMap("Attribute Type Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.6", new SyntaxMap("Bit String", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.7", new SyntaxMap("Boolean", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.11", new SyntaxMap("Country String", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.14", new SyntaxMap("Delivery Method", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.15", new SyntaxMap("Directory String", "&higgins;NormalizedStringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.16", new SyntaxMap("DIT Content Rule Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.17", new SyntaxMap("DIT Structure Rule Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.12", new SyntaxMap("DN", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.21", new SyntaxMap("Enhanced Guide", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.22", new SyntaxMap("Facsimile Telephone Number", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.23", new SyntaxMap("Fax", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.24", new SyntaxMap("Generalized Time", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.25", new SyntaxMap("Guide", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.26", new SyntaxMap("IA5 String", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.27", new SyntaxMap("Integer", "&higgins;IntegerSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.28", new SyntaxMap("JPEG", "&higgins;Base64BinarySimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.54", new SyntaxMap("LDAP Syntax Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.30", new SyntaxMap("Matching Rule Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.31", new SyntaxMap("Matching Rule Use Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.34", new SyntaxMap("Name and Optional UID", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.35", new SyntaxMap("Name Form Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.36", new SyntaxMap("Numeric String", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.37", new SyntaxMap("Object Class Description", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.40", new SyntaxMap("Octet String", "&higgins;Base64BinarySimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.38", new SyntaxMap("OID", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.39", new SyntaxMap("Other Mailbox", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.41", new SyntaxMap("Postal Address", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.44", new SyntaxMap("Printable String", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.58", new SyntaxMap("Substring Assertion", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.50", new SyntaxMap("Telephone Number", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.51", new SyntaxMap("Teletex Terminal Identifier", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.52", new SyntaxMap("Telex Number", "&higgins;StringSimpleAttribute"));
		_syntaxHashMap.put("1.3.6.1.4.1.1466.115.121.1.53", new SyntaxMap("UTC Time", "&higgins;StringSimpleAttribute"));
	}

	/**
	 */
	private void _initAttrInMap()
	{
		Vector<String> attrs = new Vector<String>();

		attrs.add("givenname");
		attrs.add("2.5.4.42");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"), attrs);
		
		attrs = new Vector<String>();
		attrs.add("sn");
		attrs.add("surname");
		attrs.add("2.5.4.4");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), attrs);

		attrs = new Vector<String>();
		attrs.add("mail");
		attrs.add("email");
		attrs.add("emailaddress");
		attrs.add("internetaddress");
		attrs.add("rfc822mailbox");
		attrs.add("1.2.840.113549.1.9.1");
		attrs.add("0.9.2342.19200300.100.1.3");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"), attrs);

		attrs = new Vector<String>();
		attrs.add("street");
		attrs.add("streetaddress");
		attrs.add("2.5.4.9");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress"), attrs);

		attrs = new Vector<String>();
		attrs.add("localityName");
		attrs.add("2.5.4.7");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality"), attrs);

		attrs = new Vector<String>();
		attrs.add("st");
		attrs.add("stateprovincename");
		attrs.add("2.5.4.8");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince"), attrs);

		attrs = new Vector<String>();
		attrs.add("postalcode");
		attrs.add("2.5.4.17");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode"), attrs);

		attrs = new Vector<String>();
		attrs.add("c");
		attrs.add("countryname");
		attrs.add("2.5.4.6");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country"), attrs);

		attrs = new Vector<String>();
		attrs.add("telephonenumber");
		attrs.add("homephone");
		attrs.add("2.5.4.20");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone"), attrs);

		attrs = new Vector<String>();
		attrs.add("otherphone");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/otherphone"), attrs);

		attrs = new Vector<String>();
		attrs.add("mobilephone");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone"), attrs);

		attrs = new Vector<String>();
		attrs.add("dateofbirth");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth"), attrs);

		attrs = new Vector<String>();
		attrs.add("gender");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender"), attrs);

		attrs = new Vector<String>();
		attrs.add("guid");
		attrs.add("privatepersonalidentifier");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier"), attrs);

		attrs = new Vector<String>();
		attrs.add("groupmembership");
		_attrInHashMap.put(new CIStringKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groupmembership"), attrs);
	}

	/**
	 */
	private void _initAttrOutMap()
	{
		_attrOutHashMap.put(new CIStringKey("givenname"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");
		_attrOutHashMap.put(new CIStringKey("2.5.4.42"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");

		_attrOutHashMap.put(new CIStringKey("sn"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");
		_attrOutHashMap.put(new CIStringKey("surname"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");
		_attrOutHashMap.put(new CIStringKey("2.5.4.4"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");

		_attrOutHashMap.put(new CIStringKey("mail"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
		_attrOutHashMap.put(new CIStringKey("email"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
		_attrOutHashMap.put(new CIStringKey("emailaddress"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
		_attrOutHashMap.put(new CIStringKey("internetaddress"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
		_attrOutHashMap.put(new CIStringKey("rfc822mailbox"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
		_attrOutHashMap.put(new CIStringKey("1.2.840.113549.1.9.1"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
		_attrOutHashMap.put(new CIStringKey("0.9.2342.19200300.100.1.3"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");

		_attrOutHashMap.put(new CIStringKey("street"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress");
		_attrOutHashMap.put(new CIStringKey("streetaddress"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress");
		_attrOutHashMap.put(new CIStringKey("2.5.4.9"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress");

		_attrOutHashMap.put(new CIStringKey("localityName"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality");
		_attrOutHashMap.put(new CIStringKey("2.5.4.7"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality");

		_attrOutHashMap.put(new CIStringKey("st"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince");
		_attrOutHashMap.put(new CIStringKey("stateorprovincename"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince");
		_attrOutHashMap.put(new CIStringKey("2.5.4.8"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince");

		_attrOutHashMap.put(new CIStringKey("postalcode"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode");
		_attrOutHashMap.put(new CIStringKey("2.5.4.17"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode");

		_attrOutHashMap.put(new CIStringKey("c"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country");
		_attrOutHashMap.put(new CIStringKey("countryname"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country");
		_attrOutHashMap.put(new CIStringKey("2.5.4.6"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country");

		_attrOutHashMap.put(new CIStringKey("telephonenumber"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone");
		_attrOutHashMap.put(new CIStringKey("2.5.4.20"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone");
		_attrOutHashMap.put(new CIStringKey("homephone"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone");

		_attrOutHashMap.put(new CIStringKey("otherphone"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/otherphone");
		_attrOutHashMap.put(new CIStringKey("mobilephone"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone");
		_attrOutHashMap.put(new CIStringKey("dateofbirth"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth");
		_attrOutHashMap.put(new CIStringKey("gender"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender");
		_attrOutHashMap.put(new CIStringKey("privatepersonalidentifier"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier");
		_attrOutHashMap.put(new CIStringKey("guid"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier");

		_attrOutHashMap.put(new CIStringKey("groupmembership"), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groupmembership");
	}

	/**
	 * @throws IdASException 
	 */
	private void _emitXDASRecord(
		int iEventNumber,
		int iOutcome,
		String sInitiatorInfo,
		String sTargetInfo,
		String sEventInfo) throws IdASException
	{
		if (_xdasSession != null)
		{
			if (sTargetInfo == null)
				sTargetInfo = "";
			if (sEventInfo == null)
				sEventInfo = "";
			try
			{
				XDasRecord xdasRecord = _xdasSession.XDasStartRecord(XDasEvents.XDAS_AE_TERMINATE_SESSION, XDasOutcomes.XDAS_OUT_SUCCESS,
						sInitiatorInfo, sTargetInfo, sEventInfo);
				xdasRecord.commit();
			}
			catch (XDasException e)
			{
				throw new IdASException(e);
			}
			catch (IOException e)
			{
				throw new IdASException(e);
			}
		}
	}

	/**
	 */
	public void open(
		Object identity) throws IdASException
	{
		if (_bIsOpen)
			throw new ContextOpenException();

		

		// Override specific environment elements.
		if (identity instanceof AuthNNamePasswordMaterials)
		{
			Results results = new Results(this.globalChain);
			try {
				ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
				attrs.add(new net.sourceforge.myvd.types.Attribute("1.1"));
				this.myvdSearch(this.searchBase, 2, "(" + this.uidAttrib + "=" + ((AuthNNamePasswordMaterials) identity).getUsername() + ")", attrs, results);
				results.start();
				
				if (results.hasMore()) {
					Entry entry = results.next();
					String dn = entry.getEntry().getDN();
					if (results.hasMore()) {
						throw new IdASException("User id is not unique");
					}
					
					try
			        {
			            
						DistinguishedName bindDN = (DistinguishedName) userSession.get("MYVD_BINDDN");
					    Password pass = (Password) userSession.get("MYVD_BINDPASS");
					    
					    if (bindDN == null) {
					    	bindDN = new DistinguishedName("");
					    	pass = new Password();
					    	
					    	
					    	
					    	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
					       
					    }
			            
			            DistinguishedName newBindDN = new DistinguishedName(dn);
			            Password newPass = new Password(((AuthNNamePasswordMaterials)identity).getPassword());
			            
			            BindInterceptorChain chain = new BindInterceptorChain(bindDN,pass,0,this.globalChain,userSession,this.createUserRequest(),router);
			            chain.nextBind(newBindDN,newPass,new LDAPConstraints());
			            
			            userSession.put("MYVD_BINDDN",newBindDN);
			            userSession.put("MYVD_BINDPASS",newPass);
			            
			        }
			        catch( LDAPException e )
			        {
			           
			        	//bind failed, reset the session username and pass
			        	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			        	userSession.put("MYVD_BINDDN",new DistinguishedName(""));
			        	userSession.put("MYVD_BINDPASS",new Password());
			        	
			        	throw new IdASException(e);
			        }
				} else {
					throw new IdASException("User not found");
				}
			} catch (LDAPException e) {
				throw new IdASException(e);
			} finally {
				try {
					results.finish();
				} catch (LDAPException e) {
					throw new IdASException(e);
				}
			}
			
		    
		    
		    
		    
			//_env.put(Context.SECURITY_AUTHENTICATION, "simple");
			//_env.put(Context.SECURITY_PRINCIPAL, mapNameIn(((AuthNNamePasswordMaterials)identity).getUsername()));
			//_env.put(Context.SECURITY_CREDENTIALS, ((AuthNNamePasswordMaterials)identity).getPassword());
		}
		// TODO: Support more auth types.

		
			
			
			
			//_ctx = new InitialLdapContext(_env, null);
			_emitXDASRecord(XDasEvents.XDAS_AE_CREATE_SESSION, XDasOutcomes.XDAS_OUT_SUCCESS,
					_contextRef.toString(), null, null);
		
		_bIsOpen = true;
	}

	/**
	 */
	public String mapNameIn(String externalName)
	{
		StringBuffer out = new StringBuffer(externalName);
		
		//TODO do some mapping here
		
		return out.toString();
	}

	/**
	 */
	public String mapNameOut(String internalName)
	{
		DN dn = new DN(internalName);
		
		return ((RDN) dn.getRDNs().get(0)).getValue();
		
		
		
		
	}
	
	/**
	 */
	public void close() throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		_bIsOpen = false;
		this.server.stopServer();
		_emitXDASRecord(XDasEvents.XDAS_AE_TERMINATE_SESSION, XDasOutcomes.XDAS_OUT_SUCCESS,
				_contextRef.toString(), null, null);
		
	}

	/**
	 */
	public boolean isOpen(
		Object identity) throws IdASException
	{
		return _bIsOpen;
	}

	/**
	 */
	private DOMDocument _getInitialSchemaDoc()
	{
		/* Create an OWL document in RDF representing the schema. */
		DOMDocument doc = new DOMDocument();
		Vector<InternalEntityDecl> entityDeclList = new Vector<InternalEntityDecl>();

		entityDeclList.add(new InternalEntityDecl("ldapowl", "http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap#"));
		entityDeclList.add(new InternalEntityDecl("higgins", "http://www.eclipse.org/higgins/ontologies/2006/higgins#"));
		entityDeclList.add(new InternalEntityDecl("xsd", "http://www.w3.org/2001/XMLSchema#"));

		DefaultDocumentType docType = new DefaultDocumentType();
		docType.setInternalDeclarations(entityDeclList);
		docType.setName("rdf:RDF");
		doc.setDocType(docType);
		doc.addComment("\r\n*******************************************************************************\r\n" +
				"* Copyright (c) 2006 Novell Inc.\r\n" +
				"* All rights reserved. This document and accompanying materials\r\n" + 
				"* are made available under the terms of the Eclipse Public License v1.0\r\n" +
				"* which accompanies this distribution, and is available at\r\n" +
				"* http://www.eclipse.org/legal/epl-v10.html\r\n" +
				"*\r\n" +
				"* Contributors:\r\n" +
				"*     Tom Doman (http://www.bandit-project.org)\r\n" +
				"*     Jim Sermersheim (http://www.bandit-project.org)\r\n" +
				"*******************************************************************************\r\n");

		DOMElement elem = (DOMElement)doc.addElement("rdf:RDF");
		elem.addAttribute("xml:base", "http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap#");
		elem.addNamespace("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
		elem.addNamespace("rdfs", "http://www.w3.org/2000/01/rdf-schema#");
		elem.addNamespace("owl", "http://www.w3.org/2002/07/owl#");
		elem.addNamespace("ldapowl", "http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap#");		

		DOMElement ontElem = (DOMElement)elem.addElement("owl:Ontology");
		ontElem.addAttribute("rdf:about", "");
		DOMElement childElem = (DOMElement)ontElem.addElement("rdfs:label");
		childElem.addText("Dynamically Generated Higgins-based LDAP Ontology (Context: " + _contextRef.toString() + ")");
		childElem = (DOMElement)ontElem.addElement("owl:imports");
		childElem.addAttribute("rdf:resource", "http://www.eclipse.org/higgins/ontologies/2006/higgins.owl");

		ontElem = (DOMElement)elem.addElement("owl:Ontology");
		ontElem.addAttribute("rdf:about", "http://www.eclipse.org/higgins/ontologies/2006/higgins.owl");

		return (doc);
	}

	/**
	 */
	private void _getSchemaClass(
		DOMDocument schemaDoc,
		String schemaName,
		LDAPObjectClassSchema objSchema) throws IdASException
	{
		boolean bFoundSup = false;
		DOMElement rootElem = (DOMElement)schemaDoc.getRootElement(),
				   classElem, childElem;

		rootElem.addComment(schemaName);
		classElem = (DOMElement)rootElem.addElement("owl:Class");			
		classElem.addAttribute("rdf:ID", "class_" + schemaName);
		childElem = (DOMElement)classElem.addElement("rdfs:label");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(schemaName);

		String[] sups = objSchema.getSuperiors();
		
		if (sups != null) {
			for (int i=0;i<sups.length;i++) {
				childElem = (DOMElement)classElem.addElement("rdfs:subClassOf");
				childElem.addAttribute("rdf:resource", "#class_" + sups[i]);
				bFoundSup = true;
			}
		}
		
		//set the oid
		Object oid = objSchema.getID();
		childElem = (DOMElement)classElem.addElement("owl:equivalentClass");
		childElem.addAttribute("rdf:resource", "urn:oid:" + oid);
		// Define equivalent class.
		DOMElement oidClassElem = (DOMElement)rootElem.addElement("owl:Class");
		oidClassElem.addAttribute("rdf:about", "urn:oid:" + oid);
		childElem = (DOMElement)oidClassElem.addElement("rdfs:label");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(schemaName);					
		
		//add "may"
		String[] may = objSchema.getOptionalAttributes();
		if (may != null) {
			for (int i=0;i<may.length;i++) {
				_addAttributeDomain(schemaName, may[i]);
			}
		}
		
		String[] must = objSchema.getRequiredAttributes();
		if (must != null) {
			for (int i=0;i<must.length;i++) {
				String attrName = must[i];
				DOMElement subClassElem = (DOMElement)classElem.addElement("rdfs:subClassOf");
				DOMElement restrictElem = (DOMElement)subClassElem.addElement("owl:Restriction");
	
				_addAttributeDomain(schemaName, attrName);
				childElem = (DOMElement)restrictElem.addElement("owl:onProperty");
				childElem.addAttribute("rdf:resource", _mapAttrToString(attrName));
				childElem = (DOMElement)restrictElem.addElement("owl:minCardinality");
				childElem.addAttribute("rdf:datatype", "&xsd;nonNegativeInteger");
				childElem.addText("1");
			}
		}
		
		childElem = (DOMElement)classElem.addElement("rdfs:comment");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(objSchema.getDescription());
		
		if (!bFoundSup)
		{
			childElem = (DOMElement)classElem.addElement("rdfs:subClassOf");
			childElem.addAttribute("rdf:resource", "&higgins;DigitalSubject");
		}
	}

	/**
	 */
	private String _getAttributeNameCase(
		String attrName)
	{
		String attrCaseName = attrName;
		//TODO: Need the schema cache for this as well as other things.
		if (_schemaAttrCaseHashMap != null)
		{
			CIStringKey ciAttrName = new CIStringKey(attrName);

			attrCaseName = _schemaAttrCaseHashMap.get(ciAttrName);
			if (attrCaseName == null)
			{
				_schemaAttrCaseHashMap.put(ciAttrName, attrName);
				attrCaseName = attrName;
			}
		}
		return attrCaseName;
	}

	/**
	 */
	private void _addAttributeDomain(
		String className,
		String attrName)
	{
		CIStringKey ciAttrName = new CIStringKey(attrName);

		Vector<String> classNameVect = _schemaAttrDomainHashMap.get(ciAttrName);
		if (classNameVect == null)
			classNameVect = new Vector<String>();
		classNameVect.add(className);

		_schemaAttrDomainHashMap.put(ciAttrName, classNameVect);
	}

	/**
	 */
	private Vector<String> _getAttrDomains(String schemaName)
	{
		CIStringKey ciAttrName = new CIStringKey(schemaName);

		return _schemaAttrDomainHashMap.get(ciAttrName);
	}

	/**
	 */
	private void _getSchemaAttrDef(
		DOMDocument schemaDoc,
		String schemaName,
		LDAPAttributeSchema attrSchema) throws IdASException
	{
		DOMElement rootElem = (DOMElement)schemaDoc.getRootElement(),
				   propertyElem, childElem;

		rootElem.addComment(schemaName);
		propertyElem = (DOMElement)rootElem.addElement("owl:ObjectProperty");
		propertyElem.addAttribute("rdf:about", _mapAttrToString(schemaName));
		childElem = (DOMElement)propertyElem.addElement("rdfs:label");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(schemaName);

		boolean bFoundSup = false;
		
		String sup = attrSchema.getSuperior();
		childElem = (DOMElement)propertyElem.addElement("rdfs:subPropertyOf");
		if (sup != null) {
			childElem.addAttribute("rdf:resource", _mapAttrToString(sup));
		}
		bFoundSup = true;
		
		String oid = attrSchema.getID();
		
		childElem = (DOMElement)propertyElem.addElement("owl:equivalentProperty");
		childElem.addAttribute("rdf:resource", "urn:oid:" + oid);
		// Define equivalent property.
		DOMElement oidPropertyElem = (DOMElement)rootElem.addElement("owl:ObjectProperty");
		oidPropertyElem.addAttribute("rdf:about", "urn:oid:" + oid);
		childElem = (DOMElement)oidPropertyElem.addElement("rdfs:label");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(schemaName);
		
		String syntax = attrSchema.getSyntaxString();
		String syntaxOID = attrSchema.getSyntaxString();
		
		if (syntax != null) {
		
			if (syntax.indexOf('{') > 0)
				syntaxOID = syntax.substring(0, syntax.indexOf('{'));
			// Create the reference to the syntax class we'll define later.
			childElem = (DOMElement)propertyElem.addElement("rdfs:range");
			SyntaxMap syntaxMap = _syntaxHashMap.get(syntaxOID);
			childElem.addAttribute("rdf:resource", syntaxMap == null ? ("urn:oid:" + syntaxOID) : ("#" + syntaxMap.getURLName()));
			
			childElem = (DOMElement)propertyElem.addElement("rdfs:comment");
			childElem.addAttribute("rdf:datatype", "&xsd;string");
			childElem.addText(syntax);
		}
		if (attrSchema.isSingleValued()) {
			DOMElement singleValElem = (DOMElement)rootElem.addElement("rdf:Description");
			singleValElem.addAttribute("rdf:about", "#class_top");
			DOMElement subClassElem = (DOMElement)singleValElem.addElement("rdfs:subClassOf");
			DOMElement restrictElem = (DOMElement)subClassElem.addElement("owl:Restriction");
			childElem = (DOMElement)restrictElem.addElement("owl:maxCardinality");
			childElem.addText("1");
			childElem = (DOMElement)restrictElem.addElement("owl:onProperty");
			childElem.addAttribute("rdf:resource", _mapAttrToString(schemaName));
		}
		
		
		String name = attrSchema.getName();
		if (schemaName.compareTo(name) != 0)
		{
			childElem = (DOMElement)propertyElem.addElement("owl:equivalentProperty");
			childElem.addAttribute("rdf:resource", _mapAttrToString(name));
			// Define equivalent property.
			DOMElement equivPropertyElem = (DOMElement)rootElem.addElement("owl:ObjectProperty");
			equivPropertyElem.addAttribute("rdf:about", _mapAttrToString(name));
			childElem = (DOMElement)equivPropertyElem.addElement("rdfs:label");
			childElem.addAttribute("rdf:datatype", "&xsd;string");
			childElem.addText(schemaName);
		}
		
		

		// Add references to all the classes that this attribute is legal on.
		Vector<String> attrClasses = _getAttrDomains(schemaName);
		if (attrClasses != null)
		{
			for (int iLoop = 0; iLoop < attrClasses.size(); ++iLoop)
			{
				childElem = (DOMElement)propertyElem.addElement("rdfs:domain");
				childElem.addAttribute("rdf:resource", "#class_" + attrClasses.get(iLoop));
			}
		}
		// Add the subproperty of the property.
		if (!bFoundSup)
		{
			childElem = (DOMElement)propertyElem.addElement("rdfs:subPropertyOf");
			childElem.addAttribute("rdf:resource", "&higgins;attribute");
		}
	}

	/**
	 */
	private void _getSchemaSyntaxDef(
		DOMDocument schemaDoc,
		String schemaName,
		LDAPSyntaxSchema syntaxSchema) throws IdASException
	{
		DOMElement rootElem = (DOMElement)schemaDoc.getRootElement(),
				   classElem, childElem;
		SyntaxMap syntaxMap = _syntaxHashMap.get(schemaName);

		if (syntaxMap == null)
			rootElem.addComment(schemaName);
		else
			rootElem.addComment(syntaxMap.getLabel());

		classElem = (DOMElement)rootElem.addElement("owl:Class");
		if (syntaxMap == null)
			classElem.addAttribute("rdf:about", "urn:oid:" + schemaName);
		else
			classElem.addAttribute("rdf:ID", syntaxMap.getURLName());
		childElem = (DOMElement)classElem.addElement("rdfs:label");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(syntaxMap == null ? schemaName : syntaxMap.getLabel());
		childElem = (DOMElement)classElem.addElement("rdfs:subClassOf");
		childElem.addAttribute("rdf:resource", syntaxMap == null ? "&higgins;StringSimpleAttribute" : syntaxMap.getOWLType());

		childElem = (DOMElement)classElem.addElement("rdfs:comment");
		childElem.addAttribute("rdf:datatype", "&xsd;string");
		childElem.addText(syntaxSchema.getDescription());
		
		if (syntaxMap != null)
		{					
			Object oid = syntaxSchema.getID();
			childElem = (DOMElement)classElem.addElement("owl:equivalentClass");
			childElem.addAttribute("rdf:resource", "urn:oid:" + oid);

			// Define equivalent class.
			DOMElement oidClassElem = (DOMElement)rootElem.addElement("owl:Class");
			oidClassElem.addAttribute("rdf:about", "urn:oid:" + oid);
			childElem = (DOMElement)oidClassElem.addElement("rdfs:label");
			childElem.addAttribute("rdf:datatype", "&xsd;string");
			childElem.addText(syntaxMap.getLabel());
		}
	}

	/**
	 */
	public String getSchema() throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		if (_schemaAttrDomainHashMap == null)
			_schemaAttrDomainHashMap = new HashMap<CIStringKey, Vector<String>>();
		else
			_schemaAttrDomainHashMap.clear();

		if (_schemaAttrCaseHashMap == null)
			_schemaAttrCaseHashMap = new HashMap<CIStringKey, String>();
		else
			_schemaAttrCaseHashMap.clear();

		DOMDocument schemaDoc = _getInitialSchemaDoc();
		//TODO: Get the schema associated with the identity used to open this
		//		context instead of the root.
		try
		{
			
			
			LDAPSchema schema = getRemoteSchema();
			
			// The OWL generator depends on these containers being visited in this order.
			Vector<String>schemaContainers = new Vector<String>();
			schemaContainers.add("ClassDefinition");
			schemaContainers.add("AttributeDefinition");
			schemaContainers.add("SyntaxDefinition");

			//First the class defenitions
			Enumeration enumer = schema.getObjectClassNames();
			
			while (enumer.hasMoreElements()) {
				String objectClassName = (String) enumer.nextElement();
				LDAPObjectClassSchema objSchema = schema.getObjectClassSchema(objectClassName);
				
				
				DOMElement rootElem = (DOMElement)schemaDoc.getRootElement();
				rootElem.addComment("ClassDefinition");
				_getSchemaClass(schemaDoc, objSchema.getName(), objSchema);
			}
			
			enumer = schema.getAttributeSchemas();
			while (enumer.hasMoreElements()) {
				LDAPAttributeSchema attrSchema = (LDAPAttributeSchema) enumer.nextElement();
				DOMElement rootElem = (DOMElement)schemaDoc.getRootElement();
				rootElem.addComment("AttributeDefinition");
				_getSchemaAttrDef(schemaDoc, attrSchema.getName(), attrSchema);
			}
			
			enumer = schema.getSyntaxSchemas();
			
			while (enumer.hasMoreElements()) {
				LDAPSyntaxSchema syntaxSchema = (LDAPSyntaxSchema) enumer.nextElement();
				DOMElement rootElem = (DOMElement)schemaDoc.getRootElement();
				rootElem.addComment("SyntaxDefinition");
				_getSchemaSyntaxDef(schemaDoc, syntaxSchema.getName(), syntaxSchema);
			}
			
			
		}
		catch (LDAPException e) {
			throw new IdASException(e);
		}

		StringWriter strWriter = new StringWriter();
		NonEscapedAttrXMLWriter xmlWriter = new NonEscapedAttrXMLWriter(strWriter);
		try
		{
			xmlWriter.write(schemaDoc);
		}
		catch (IOException e)
		{
			throw new IdASException(e);
		}
		return strWriter.toString();
	}

	private LDAPSchema getRemoteSchema() throws LDAPException, IdASException {
		Results res = new Results(this.globalChain);
		
		ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
		attrs.add(new net.sourceforge.myvd.types.Attribute("objectClasses"));
		attrs.add(new net.sourceforge.myvd.types.Attribute("attributeTypes"));
		attrs.add(new net.sourceforge.myvd.types.Attribute("ldapSyntaxes"));
		
		
		
		this.myvdSearch("cn=schema", 0, "(objectClass=*)", attrs, res);
		
		res.start();
		
		if (! res.hasMore()) {
			throw new IdASException("No Schema Defined");
		}
		
		LDAPEntry entry = res.next().getEntry();
		
		LDAPSchema schema = new LDAPSchema(entry);
		return schema;
	}

	/**
	 */
	public URI getContextRef() throws IdASException
	{
		return _contextRef;
	}

	/**
	 */
	public String exportData(
		String arg0,
		String arg1) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public void importData(
		String arg0,
		String arg1) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public IDigitalSubject getSubject(
		String cuid) throws IdASException
	{
		return getSubject(cuid, null);
	}
	/**
	 */
	public IDigitalSubject getSubject(
		String cuid,
		Iterable<URI> attrSelectionList) throws IdASException		
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		_emitXDASRecord(XDasEvents.XDAS_AE_QUERY_DATA_ITEM_ATT, XDasOutcomes.XDAS_OUT_SUCCESS,
				_contextRef.toString(), cuid, null);
		String name = mapNameIn(cuid);
		MyVDDigitalSubject subject = null;
		
		SearchControls controls = new SearchControls();
		ArrayList<net.sourceforge.myvd.types.Attribute> attribs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
		
		if (attrSelectionList != null)
		{
			Vector<String> mappedAttrs = new Vector<String>();
			Vector<String> inMappedAttrs;
			for (URI attrName : attrSelectionList)
			{
				inMappedAttrs = _attrInHashMap.get(new CIStringKey(attrName.toString()));
				for (String inAttr : inMappedAttrs)
					//mappedAttrs.add(inAttr);
					attribs.add(new net.sourceforge.myvd.types.Attribute(inAttr));
			}
//			controls.setReturningAttributes(mappedAttrs.toArray(new String[0]));
		}
		//controls.setSearchScope(SearchControls.OBJECT_SCOPE);
		try
		{
			Results results = new Results(this.globalChain);
			//System.out.println("NAME : " + name);
			if (name.indexOf('=') != -1) {
				//the name is a DN, lets do a base search
				this.myvdSearch(name, 0, "(objectClass=*)", attribs,results);
			} else {
				//the name is an ID so we will do a search from the base
				this.myvdSearch(this.searchBase, 2, "(" + this.uidAttrib + "=" + name + ")", attribs,results);
			}
			
			
			//results = _ctx.search(name, "(objectclass=*)", controls);

			
			
			results.start();
			
			if (results.hasMore())
			{
				Entry entry = results.next();
				if (results.hasMore()) throw new IdASException("Non-unique CUID");
				subject = new MyVDDigitalSubject(this, entry);
			}
		}
		catch (LDAPException e)
		{
			throw new IdASException(e);
		}

		return subject;
	}

	/**
	 */
	private void _convertFilter(
		BasicFilter basicFilter,
		RfcFilter ldapFilter) throws IdASException
	{
		try
		{
			BasicFilterAssertion assertion = (BasicFilterAssertion)basicFilter.getAssertion();
			if (assertion != null)
			{
				URI attrURI = assertion.getType();
				String comparator = assertion.getComparator();
				int rfcType = _mapComparator(comparator);

				if (assertion instanceof BasicFilterAttributeAssertion)
				{
					BasicFilterAttributeAssertion attributeAssertion = (BasicFilterAttributeAssertion)assertion;
					IPropertyValue assertionValue = attributeAssertion.getAssertionValue();
					String attrFragment = attrURI.getFragment(), attrName = attrFragment.substring(attrFragment.indexOf("attr_") + 5);

					if (assertionValue == null)
					{
						switch (rfcType)
						{
						case RfcFilter.PRESENT:
							ldapFilter.addPresent(attrName);
							break;
						default:
							throw new NotImplementedException("Comparator (" + comparator + ") not supported.");
						}
					}
					else if (assertionValue.isSimple())
					{
						Object valueData = assertionValue.getData();
						//assertionValue.getType();					

						switch (rfcType)
						{
						case RfcFilter.EQUALITY_MATCH:
						case RfcFilter.GREATER_OR_EQUAL:
						case RfcFilter.LESS_OR_EQUAL:
							if (valueData instanceof String)
								ldapFilter.addAttributeValueAssertion(rfcType, attrName, ((String)valueData).getBytes());
							else if (valueData instanceof byte[])
								ldapFilter.addAttributeValueAssertion(rfcType, attrName, (byte [])valueData);
							else
								ldapFilter.addAttributeValueAssertion(rfcType, attrName, ((ISimpleValue)assertionValue).getLexical().getBytes());
							break;
						//TODO: Handle substrings
//						case RfcFilter.SUBSTRINGS:
//							ldapFilter.startSubstrings();
//							break;
//						case RfcFilter.EXTENSIBLE_MATCH:
//							break;
						default:
							throw new NotImplementedException("Comparator (" + comparator + ") not supported.");
						}
					}
					else
					{
						throw new NotImplementedException("Complex assertion values in filters not supported.");
					}
				}
			}
			else
			{
				String operator = basicFilter.getOperator();
				int rfcType = _mapOperator(operator);

				if (rfcType == -1)
					throw new NotImplementedException("Operator (" + operator + ") not supported.");

				ldapFilter.startNestedFilter(rfcType);
				Iterable<IFilter> filters = basicFilter.getFilters();
				for (IFilter filter : filters)
					_convertFilter((BasicFilter)filter, ldapFilter);
				ldapFilter.endNestedFilter(rfcType);
			}
		}
		catch (LDAPLocalException e)
		{
			throw new IdASException(e);
		}
	}

	/**
	 */
	private int _mapComparator(
		String comparator)
	{
		int iRet = -1;

		if (comparator.compareTo(IFilterPropertyAssertion.COMP_PROP_EQ) == 0)
			iRet = RfcFilter.EQUALITY_MATCH;
		else if (comparator.compareTo(IFilterPropertyAssertion.COMP_PROP_GE) == 0) 
			iRet = RfcFilter.GREATER_OR_EQUAL;
		else if (comparator.compareTo(IFilterPropertyAssertion.COMP_PROP_LE) == 0)
			iRet = RfcFilter.LESS_OR_EQUAL;
		else if (comparator.compareTo(IFilterPropertyAssertion.COMP_PROP_PRESENT) == 0)
			iRet = RfcFilter.PRESENT;
		else if (comparator.compareTo(IFilterPropertyAssertion.COMP_PROP_SUBSTR) == 0)
			iRet = RfcFilter.SUBSTRINGS;

		return iRet;
	}

	/**
	 */
	private int _mapOperator(
		String operator)
	{
		int iRet = -1;

		if (operator.compareTo(IFilter.OP_NOT) == 0)
			iRet = RfcFilter.NOT;
		else if (operator.compareTo(IFilter.OP_AND) == 0)
			iRet = RfcFilter.AND;
		else if (operator.compareTo(IFilter.OP_OR) == 0)
			iRet = RfcFilter.OR;

		return iRet;
	}

	public Iterable<IDigitalSubject> getSubjects(
		IFilter filter
		) throws IdASException
	{
		return getSubjects(filter, null);
	}
	/**
	 */
	public Iterable<IDigitalSubject> getSubjects(
		IFilter filter,
		Iterable<URI> attrSelectionList) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		_emitXDASRecord(XDasEvents.XDAS_AE_QUERY_DATA_ITEM_ATT, XDasOutcomes.XDAS_OUT_SUCCESS,
				_contextRef.toString(), filter.toString(), null);

		HashSet<IDigitalSubject> subs = new HashSet<IDigitalSubject>();
		String strFilter = "(objectclass=*)";

		if (filter != null)
		{
			BasicFilter basicFilter = (BasicFilter)filter;
			// Convert the IdAS filter to an LDAP filter.
			RfcFilter ldapFilter = new RfcFilter();
			_convertFilter(basicFilter, ldapFilter);
			strFilter = ldapFilter.filterToString();
		}
		try
		{
			MyVDDigitalSubject subject;
			ArrayList<net.sourceforge.myvd.types.Attribute> attribs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
			if (attrSelectionList != null)
			{
				Vector<String> mappedAttrs = new Vector<String>();
				Vector<String> inMappedAttrs;
				for (URI attrName : attrSelectionList)
				{
					inMappedAttrs = _attrInHashMap.get(new CIStringKey(attrName.toString()));
					for (String inAttr : inMappedAttrs)
						attribs.add(new net.sourceforge.myvd.types.Attribute(inAttr));
				}
				
			}
			
			//System.out.println("strFilter : " + strFilter);
			

			Results res = new Results(this.globalChain);
			this.myvdSearch(this.searchBase, 2, strFilter, attribs, res);
			
			res.start();
			
			while (res.hasMore())
			{
				Entry entry = res.next();
				subject = new MyVDDigitalSubject(this, entry);
				subs.add(subject);
			}
		}
		catch (LDAPException e)
		{
			throw new IdASException(e);
		}

		return subs;
	}

	/**
	 */
	public IDigitalSubject createSubject(
		URI cuid,
		Iterable<IAttribute> attrs) throws IdASException
	{
		return createSubject(cuid, null, attrs, false); 
	}
	
	/**
	 */	
	public IDigitalSubject createSubject(
		URI arg0,
		String arg1,
		Iterable<IAttribute> arg2,
		boolean arg3) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();
		
		throw new NotImplementedException();
	}

	/**
	 */
	public IDigitalSubject createSubject(
		URI arg0,
		String arg1,
		Iterable<IAttribute> arg2) throws IdASException
	{
		return createSubject(arg0, arg1, arg2, false); 
	}

	/**
	 */
	public IDigitalSubject createSubject(
		URI arg0,
		Iterable<IAttribute> arg1,
		boolean arg2) throws IdASException
	{
		return createSubject(arg0, null, arg1, arg2); 
	}

	/**
	 */
	public IDigitalSubject createSubject(
		URI arg0) throws IdASException
	{
		return createSubject(arg0, null, null, false); 
	}

	public String addSubject(
		IDigitalSubject arg0) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();
		
		throw new NotImplementedException();
	}
	
	/**
	 */
	public void removeSubject(
		String cuid) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public boolean verifySubjectAttributes(
		String arg0,
		Iterable<IAttribute> arg1) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public void updateSubject(
		String arg0,
		Iterable<IAttribute> arg1) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public IMetadata createMetadata(
		URI type,
		IPropertyValue value) throws IdASException
	{
		return new BasicMetadata(type, value);
	}

	/**
	 */
	public void addMetadata(
		IMetadata metadata) throws IdASException
	{
		_getMetadataSet().add(metadata);
	}

	/**
	 */
	public void	removeMetadata(
		IMetadata metadata) throws IdASException
	{
		_getMetadataSet().remove(metadata);
	}

	/**
	 */
	public Iterable<IMetadata> getMetadataSet() throws IdASException
	{
		return _getMetadataSet();
	}

	/**
	 */
	private HashSet<IMetadata> _getMetadataSet() throws IdASException
	{
		if (_metaData == null)
			_metaData = new HashSet<IMetadata>();
		return _metaData;
	}

	/**
	 */
	public IRelationship<URI> createRelationship(
		URI arg0) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public void addRelationship(
		IRelationship<URI> arg0) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public void removeRelationship(
		IRelationship<URI> arg0) throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public Iterable<IRelationship<URI>> getRelationships() throws IdASException
	{
		if (!_bIsOpen)
			throw new ContextNotOpenException();

		throw new NotImplementedException();
	}

	/**
	 */
	public IFilter createFilter() throws IdASException
	{
		return new BasicFilter();
	}

	/**
	 */
	public void setSchema(String arg0) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public URI getType(
		Entry entry) throws IdASException
	{
		String structuralClass = null;

		LDAPAttribute ocAttr = _getObjectClass(entry);
		

		if (ocAttr.size() == 1)
		{
			structuralClass = ocAttr.getStringValue();
		}
		else
		{
			String[] ocs = ocAttr.getStringValueArray();
			boolean found = false;
			for (int i=0;i<ocs.length;i++)
			{
				String jndiValue = ocs[i];
				if (_isStructural(jndiValue))
				{
					structuralClass = jndiValue;
				}
			}
		}

		if (structuralClass == null)
			throw new IdASException("No structural class found.");

		// Turn structural class name into appropriate OWL type.
		URI owlType = null;
		try
		{
			owlType = new URI("http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap#"
							+ "class_" + structuralClass);
		}
		catch (URISyntaxException e)
		{
			throw new IdASException(e);
		}
		return owlType;
	}

	/**
	 */
	private boolean _isStructural(
		String className) throws IdASException
	{
		NamingEnumeration jndiAttrValEnum;
		boolean bRet = false;

		
		

		LDAPSchema schema = null;
		try {
			schema = this.getRemoteSchema();
		} catch (LDAPException e) {
			throw new IdASException(e);
		}
		
		Enumeration enumer = schema.getObjectClassSchemas();
		
		while (enumer.hasMoreElements()) {
			LDAPObjectClassSchema objSchema = (LDAPObjectClassSchema) enumer.nextElement();
			if (objSchema.getNames()[0].equalsIgnoreCase(className)) {
				return (objSchema.getType() == LDAPObjectClassSchema.STRUCTURAL);
			}
		}

		return bRet;
	}

	/**
	 */
	private String _getSuperiorClass(
		Attributes attrs) throws IdASException
	{
		String superiorClass = null;
		NamingEnumeration<? extends Attribute> attrEnum = attrs.getAll();

		try
		{
			while(attrEnum.hasMore())
			{
				Attribute attr = (Attribute)attrEnum.next();

				NamingEnumeration<?> attrVals = attr.getAll();
				if (attr.getID().compareTo("SUP") == 0)
				{
					superiorClass = (String)attrVals.next();
				}
				else if ((attr.getID().compareTo("AUXILIARY") == 0)
						|| (attr.getID().compareTo("ABSTRACT") == 0))
				{
					superiorClass = null;
					break;
				}
			}
		}
		catch (NamingException e)
		{
			throw new IdASException(e);
		}

		return superiorClass;
	}

	/**
	 */
	private LDAPAttribute _getObjectClass(
		Entry entry) throws IdASException
	{
		LDAPAttributeSet attribs = entry.getEntry().getAttributeSet();
		Iterator it = attribs.iterator();
		LDAPAttribute retAttr = null;
		
		boolean bFoundStructural = false;

		while (it.hasNext())
		{
			LDAPAttribute jndiAttr = (LDAPAttribute) it.next();
			if (jndiAttr.getName().compareToIgnoreCase("structuralObjectClass") == 0)
			{
				bFoundStructural = true;
				
				if (jndiAttr.size() != 1)
					throw new IdASException("Only 1 value expected, found: " + jndiAttr.size());

				String jndiValue = jndiAttr.getStringValue();
				if (jndiValue.compareToIgnoreCase("top") != 0)
				{
					retAttr = jndiAttr;
					continue;
				}
			}
			else if (jndiAttr.getName().compareToIgnoreCase("objectclass") == 0)
			{
				retAttr = jndiAttr;
				if (bFoundStructural)
					continue;
			}
		}

		if (retAttr == null)
			throw new IdASException("No structural or object class found.");
		return retAttr;
	}

	/**
	 */
	private String _mapAttrToString(String jndiType) throws IdASException
	{
		//System.out.println("jndiType : " + jndiType);
		String uriStr = _attrOutHashMap.get(new CIStringKey(jndiType));
		if (uriStr == null)
			uriStr = new String(ATTR_DISAMBIGUATOR + _getAttributeNameCase(jndiType));
		return uriStr;
	}

	/**
	 */
	public URI mapAttrToURI(String jndiType) throws IdASException
	{
		String uriStr = _attrOutHashMap.get(new CIStringKey(jndiType));
		if (uriStr == null)
			uriStr = new String(DEFAULT_ATTR_TYPE_PREFIX + ATTR_DISAMBIGUATOR + _getAttributeNameCase(jndiType));
		try
		{
			return new URI(uriStr);
		}
		catch (URISyntaxException e)
		{
			throw new IdASException(e);
		}
	}
	
	private ArrayList<Result> myvdSearch(String base,int scope,String filter,ArrayList<net.sourceforge.myvd.types.Attribute> attributes,Results results) throws LDAPException {
		
		if (userSession == null) {
			this.userSession = new HashMap<Object,Object>();
		}
		
		DistinguishedName bindDN = (DistinguishedName) userSession.get("MYVD_BINDDN");
	    Password pass = (Password) userSession.get("MYVD_BINDPASS");
	    
	    if (bindDN == null) {
	    	bindDN = new DistinguishedName("");
	    	pass = new Password();
	    	
	    	
	    	
	    	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
	       
	    }
		
		HashMap<Object, Object> userRequest = createUserRequest();
	    
	    SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
	    
	    chain.nextSearch(new DistinguishedName(base), new Int(scope), new net.sourceforge.myvd.types.Filter(filter), attributes, new Bool(false), results, new LDAPSearchConstraints());
	    
	    return results.getResults();
		
	}

	private HashMap<Object, Object> createUserRequest() {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
	    
	    String addr = "";
	    String host = "";
	    String ip = "";
	    int port = 0;
	    
	    setLocalConInfo(userRequest, host, ip, port);
	    
	    addr = "";
	    host = "";
	    ip = "";
	    port = 0;
	    
	    setRemoteConInfo(userRequest, host, ip, port);
		return userRequest;
	}
	
	private void setRemoteConInfo(HashMap<Object, Object> userRequest, String host, String ip, int port) {
		userRequest.put(RequestVariables.MYVD_REMOTE_ADDR, host);
	    userRequest.put(RequestVariables.MYVD_REMOTE_IP, ip);
	    userRequest.put(RequestVariables.MYVD_REMOTE_PORT, port);
	}

	private void setLocalConInfo(HashMap<Object, Object> userRequest, String host, String ip, int port) {
		userRequest.put(RequestVariables.MYVD_LOCAL_ADDR, host);
	    userRequest.put(RequestVariables.MYVD_LOCAL_IP, ip);
	    userRequest.put(RequestVariables.MYVD_LOCAL_PORT, port);
	}
}
