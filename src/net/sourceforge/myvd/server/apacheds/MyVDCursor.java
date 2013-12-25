package net.sourceforge.myvd.server.apacheds;

import net.sourceforge.myvd.types.Results;

import org.apache.directory.api.ldap.model.cursor.AbstractCursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.schema.AttributeType;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

public class MyVDCursor extends AbstractCursor<Entry> {

	
	MyVDPartition partition;
	private Results res;
	LdapException le;
	boolean first;
	
	net.sourceforge.myvd.types.Entry buffer;

	public MyVDCursor(Results res,MyVDPartition partition) {
		this.res = res;
		le = null;
		first = true;
		buffer = null;
		this.partition = partition;
		
	}
	
	@Override
	public void after(Entry arg0) throws LdapException, CursorException {
		//Do nothing
		System.out.println();
	}

	@Override
	public void afterLast() throws LdapException, CursorException {
		
		if (le != null) {
			throw le;
		}
		
		try {
			while (res.hasMore()) res.next();
			le = null;
		} catch (LDAPException e) {
			throw MyVDPartition.generateException(e);
		}
		
	}

	@Override
	public boolean available() {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			this.le =  MyVDPartition.generateException(e);
			return true;
		}
	}

	@Override
	public void before(Entry arg0) throws LdapException, CursorException {
		System.out.println();
		
	}

	@Override
	public void beforeFirst() throws LdapException, CursorException {
		System.out.println();
		
	}

	@Override
	public boolean first() throws LdapException, CursorException {
		return this.first;
	}

	@Override
	public Entry get() throws CursorException {
		
		try {
			LDAPEntry nentry = null;
			
			if (buffer != null) {
				nentry = buffer.getEntry();
				buffer = null;
			} else {
				nentry = res.next().getEntry();
			}
			
			Entry entry = new DefaultEntry();
			
			entry.setDn(nentry.getDN());
			LDAPAttributeSet attrs = nentry.getAttributeSet();
			for (Object o : attrs) {
				LDAPAttribute a = (LDAPAttribute) o;
				String oid = "";
				
				AttributeType at;
				
				
				
				
				
				byte[][] vals = a.getByteValueArray();
				DefaultAttribute attr = new DefaultAttribute(a.getName());
				attr.add(vals);
				entry.add(attr);
				
			}
			
			return entry;
		} catch (Exception e) {
			throw new CursorException(e);
		} 
		
	}

	private String generateRandomOID() {
		String base ="9.8.7.6.5.";
		int num = (int) (Math.random() * 5000);
		
		StringBuffer b = new StringBuffer(base);
		b.append(num);
		
		if (this.partition.getSchemaManager().getAttributeType(b.toString()) == null ) {
			return b.toString();
		} else {
			return generateRandomOID();
		}
	}

	@Override
	public boolean last() throws LdapException, CursorException {
		
		try {
			while (res.hasMore()) {
				buffer = res.next();
			}
			return true;
		} catch (LDAPException e) {
			throw MyVDPartition.generateException(e);
		}
	}

	@Override
	public boolean next() throws LdapException, CursorException {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			throw MyVDPartition.generateException(e);
		}
	}

	@Override
	public boolean previous() throws LdapException, CursorException {
		
		return false;
	}

}
