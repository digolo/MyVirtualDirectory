package net.sourceforge.myvd.server.apacheds;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.filtering.BaseEntryFilteringCursor;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveAndRenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveOperationContext;
import org.apache.directory.server.core.api.interceptor.context.RenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.interceptor.context.UnbindOperationContext;
import org.apache.directory.server.core.api.partition.Partition;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class MyVDPartition implements Partition {

	InsertChain globalChain;
	Router router;
	private String id;
	private SchemaManager schemaManager;
	private Dn suffixDn;
	private CacheService cacheService;
	
	public MyVDPartition(InsertChain globalChain,Router router) {
		this.globalChain = globalChain;
		this.router = router;
	}
	
	@Override
	public void add(AddOperationContext add) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (add.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(add.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = add.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		AddInterceptorChain chain = new AddInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		
		
		LDAPAttributeSet attrs = new LDAPAttributeSet();
		for (Attribute attr : add.getEntry().getAttributes()) {
			
			LDAPAttribute lattr = attrs.getAttribute(attr.getAttributeType().getName());
			if (lattr == null) {
				lattr = new LDAPAttribute(attr.getAttributeType().getName());
				
			}
			
			lattr.addValue(attr.getBytes());
			
		}
		
		LDAPEntry nentry = new LDAPEntry(add.getEntry().getDn().getName(),attrs);
		
		LDAPConstraints cons = new LDAPConstraints();
		
		
		
		try {
			chain.nextAdd(new net.sourceforge.myvd.types.Entry(nentry),cons);
		} catch (LDAPException e) {
			throw generateException(e);
			
		}
		
	}

	@Override
	public Entry delete(DeleteOperationContext del) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (del.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(del.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = del.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new DefaultEntry();
		try {
			chain.nextSearch(new DistinguishedName(del.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), new ArrayList<net.sourceforge.myvd.types.Attribute>(), new Bool(false), res, new LDAPSearchConstraints());
			
			res.hasMore();
			LDAPEntry nentry = res.next().getEntry();
			
			
			entry.setDn(nentry.getDN());
			LDAPAttributeSet attrs = nentry.getAttributeSet();
			for (Object o : attrs) {
				LDAPAttribute a = (LDAPAttribute) o;
				byte[][] vals = a.getByteValueArray();
				for (int i=0;i<vals.length;i++) {
					entry.add(a.getName(),vals[i]);
				}
			}
		} catch (LDAPException e1) {
			throw generateException(e1);
		}
		
		
		DeleteInterceptorChain dchain = new DeleteInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		LDAPConstraints cons = new LDAPConstraints();
		
		try {
			dchain.nextDelete(new DistinguishedName(del.getDn().getName()), cons);
		} catch (LDAPException e) {
			throw generateException(e);
		}
		
		return entry;
	}

	@Override
	public void destroy() throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void dumpIndex(OutputStream arg0, String arg1) throws IOException {
		
		
	}

	@Override
	public String getId() {
		return this.id;
	}

	@Override
	public SchemaManager getSchemaManager() {
		return this.schemaManager;
	}

	@Override
	public Dn getSuffixDn() {
		return this.suffixDn;
	}

	@Override
	public boolean hasEntry(HasEntryOperationContext has) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (has.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(has.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = has.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new DefaultEntry();
		try {
			ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
			net.sourceforge.myvd.types.Attribute none = new net.sourceforge.myvd.types.Attribute("1.1");
			attrs.add(none);
			chain.nextSearch(new DistinguishedName(has.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), attrs, new Bool(false), res, new LDAPSearchConstraints());
			
			boolean more = res.hasMore();
			
			if (more) {
				res.next();
				while (res.hasMore()) res.next();
				return true;
			} else {
				return false;
			}
			
		} catch (LDAPException e1) {
			if (e1.getResultCode() == 32) {
				return false;
			} else {
				throw generateException(e1);
			}
		}
	}

	@Override
	public void initialize() throws LdapException {
		
		
	}

	@Override
	public boolean isInitialized() {
		
		return true;
	}

	@Override
	public Entry lookup(LookupOperationContext lookup) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (lookup.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(lookup.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = lookup.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new DefaultEntry();
		try {
			chain.nextSearch(new DistinguishedName(lookup.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), new ArrayList<net.sourceforge.myvd.types.Attribute>(), new Bool(false), res, new LDAPSearchConstraints());
			
			if (res.hasMore()) {
				LDAPEntry nentry = res.next().getEntry();
				
				
				
				entry.setDn(nentry.getDN());
				LDAPAttributeSet attrs = nentry.getAttributeSet();
				for (Object o : attrs) {
					LDAPAttribute a = (LDAPAttribute) o;
					byte[][] vals = a.getByteValueArray();
					for (int i=0;i<vals.length;i++) {
						entry.add(a.getName(),vals[i]);
					}
				}
				
				while (res.hasMore()) res.next();
				return entry;
			} else {
				return null;
			}
			
		} catch (LDAPException e1) {
			if (e1.getResultCode() == 32) {
				return null;
			} else {
				throw generateException(e1);
			}
			
			
		}
	}

	@Override
	public void modify(ModifyOperationContext mod) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (mod.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(mod.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = mod.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		
		for (Modification modification : mod.getModItems()) {
			LDAPModification ldapMod = new LDAPModification(modification.getOperation().getValue(),new LDAPAttribute(modification.getAttribute().getAttributeType().getName(),modification.getAttribute().getBytes()));
			mods.add(ldapMod);
		}
		
		ModifyInterceptorChain chain = new ModifyInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		LDAPConstraints cons = new LDAPConstraints();
		
		try {
			chain.nextModify(new DistinguishedName(mod.getDn().getName()), mods, cons);
		} catch (LDAPException e) {
			throw generateException(e);
		}
		
	}

	@Override
	public void move(MoveOperationContext move) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (move.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = move.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		
		RenameInterceptorChain chain = new RenameInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		LDAPConstraints cons = new LDAPConstraints();
		
		try {
			chain.nextRename(new DistinguishedName(move.getDn().getName()), new DistinguishedName(move.getRdn().getName()), new DistinguishedName(move.getNewSuperior().getName()), new Bool(true), cons);
		} catch (LDAPException e) {
			throw generateException(e);
		}
		
	}

	@Override
	public void moveAndRename(MoveAndRenameOperationContext move)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (move.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = move.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		
		RenameInterceptorChain chain = new RenameInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		LDAPConstraints cons = new LDAPConstraints();
		
		try {
			chain.nextRename(new DistinguishedName(move.getDn().getName()), new DistinguishedName(move.getNewRdn().getName()), new DistinguishedName(move.getNewSuperiorDn().getName()), new Bool(true), cons);
		} catch (LDAPException e) {
			throw generateException(e);
		}
		
	}

	@Override
	public void rename(RenameOperationContext move) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (move.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = move.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		
		RenameInterceptorChain chain = new RenameInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		LDAPConstraints cons = new LDAPConstraints();
		
		try {
			chain.nextRename(new DistinguishedName(move.getDn().getName()), new DistinguishedName(move.getNewRdn().getName()), new Bool(true), cons);
			
		} catch (LDAPException e) {
			throw generateException(e);
		}
		
	}

	@Override
	public EntryFilteringCursor search(SearchOperationContext search)
			throws LdapException {
		
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = new HashMap<Object,Object>();
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (search.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(search.getSession().getAuthenticatedPrincipal().getDn().getName());
			password = search.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		
		ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
		
		for (String attrName : search.getReturningAttributesString()) {
			attrs.add(new net.sourceforge.myvd.types.Attribute(attrName));
		}
		
		try {
			chain.nextSearch(new DistinguishedName(search.getDn().getName()), new Int(search.getScope().getScope()), new Filter(search.getFilter().toString()), attrs, new Bool(search.isTypesOnly()), res, new LDAPSearchConstraints());
		} catch (LDAPException e) {
			throw this.generateException(e);
		}
		
		return new BaseEntryFilteringCursor(new MyVDCursor(res),search,this.getSchemaManager());
	}

	@Override
	public void setCacheService(CacheService cacheService) {
		this.cacheService = cacheService;
		
	}

	@Override
	public void setId(String id) {
		this.id = id;
		
	}

	@Override
	public void setSchemaManager(SchemaManager schemaManager) {
		this.schemaManager = schemaManager;
		
	}

	@Override
	public void setSuffixDn(Dn suffixDn) throws LdapInvalidDnException {
		this.suffixDn = suffixDn;
		
	}

	@Override
	public void sync() throws Exception {
		
		
	}

	@Override
	public void unbind(UnbindOperationContext arg0) throws LdapException {
		// TODO Auto-generated method stub
		
	}
	
	public static LdapException generateException(LDAPException e) {
		LdapException ex;
		
		switch (e.getResultCode()) {
		
			
			case 1 : ex = new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(e.getMessage(), e); break;
			case 2 : ex = new org.apache.directory.api.ldap.model.exception.LdapProtocolErrorException(e.getMessage(), e); break;
			case 3 : ex = new org.apache.directory.api.ldap.model.exception.LdapTimeLimitExceededException(e.getMessage()); break;
			case 4 : ex = new org.apache.directory.api.ldap.model.exception.LdapSizeLimitExceededException(e.getMessage()); break;
			case 48:
			case 7 : ex = new org.apache.directory.api.ldap.model.exception.LdapAuthenticationNotSupportedException(ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED); break;
			case 8 : ex = new org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException(e.getMessage()); break;
			case 11 : ex = new org.apache.directory.api.ldap.model.exception.LdapAdminLimitExceededException(e.getMessage()); break;
			case 53 :
			case 12 : ex = new org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException(e.getMessage()); break;
			case 13 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoPermissionException(e.getMessage()); break;
			case 16 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(e.getMessage()); break;
			case 17 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(e.getMessage()); break;
			case 18 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException(e.getMessage()); break;
			case 21:
			case 19 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException(ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, e.getMessage());
			case 20 : ex = new org.apache.directory.api.ldap.model.exception.LdapAttributeInUseException(e.getMessage()); break;
			case 32 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException(e.getMessage()); break;
			case 34 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidDnException(e.getMessage()); break;
			case 49 : ex = new org.apache.directory.api.ldap.model.exception.LdapAuthenticationException(e.getMessage()); break;
			case 50 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoPermissionException(e.getMessage()); break;
			case 52 :
			case 51 : ex = new org.apache.directory.api.ldap.model.exception.LdapServiceUnavailableException(ResultCodeEnum.UNAVAILABLE); break;
			case 54 : ex = new org.apache.directory.api.ldap.model.exception.LdapLoopDetectedException(e.getMessage());
			case 64 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidDnException(e.getMessage()); break;
			case 65 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(e.getMessage()); break;
			case 66 : ex = new org.apache.directory.api.ldap.model.exception.LdapContextNotEmptyException(e.getMessage()); break;
			case 69 :
			case 67 : ex = new org.apache.directory.api.ldap.model.exception.LdapSchemaException(e.getMessage()); break;
			case 68 : ex = new org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException(e.getMessage()); break;
			case 71 : ex = new org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException(e.getMessage()); break;
			case 80 : ex = new org.apache.directory.api.ldap.model.exception.LdapOtherException(e.getMessage()); break;
		    		
			default : ex = new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(e.getMessage(), e); break;
		}
		
		ex.setStackTrace(e.getStackTrace());
		return ex;
	}

}
