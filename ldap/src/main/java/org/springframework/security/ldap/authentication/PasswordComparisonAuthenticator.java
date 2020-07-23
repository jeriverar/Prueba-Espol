/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.ldap.authentication.LdapAuthenticator
 * LdapAuthenticator} which compares the login password with the value stored in the
 * directory using a remote LDAP "compare" operation.
 *
 * <p>
 * If passwords are stored in digest form in the repository, then a suitable
 * {@link PasswordEncoder} implementation must be supplied. By default, passwords are
 * encoded using the {@link LdapShaPasswordEncoder}. Note that compare operations will not
 * work if salted-SHA (SSHA) passwords are used, as it is not possible to know the salt
 * value which is a random byte sequence generated by the directory.
 *
 * @author Luke Taylor
 */
public final class PasswordComparisonAuthenticator extends AbstractLdapAuthenticator {

	private static final Log logger = LogFactory.getLog(PasswordComparisonAuthenticator.class);

	private PasswordEncoder passwordEncoder = new LdapShaPasswordEncoder(KeyGenerators.shared(0));

	private String passwordAttributeName = "userPassword";

	private boolean usePasswordAttrCompare = false;

	public PasswordComparisonAuthenticator(BaseLdapPathContextSource contextSource) {
		super(contextSource);
	}

	public DirContextOperations authenticate(final Authentication authentication) {
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
				"Can only process UsernamePasswordAuthenticationToken objects");
		// locate the user and check the password

		DirContextOperations user = null;
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();

		SpringSecurityLdapTemplate ldapTemplate = new SpringSecurityLdapTemplate(getContextSource());

		for (String userDn : getUserDns(username)) {
			try {
				user = ldapTemplate.retrieveEntry(userDn, getUserAttributes());
			}
			catch (NameNotFoundException ignore) {
			}
			if (user != null) {
				break;
			}
		}

		if (user == null && getUserSearch() != null) {
			user = getUserSearch().searchForUser(username);
		}

		if (user == null) {
			throw new UsernameNotFoundException("User not found: " + username);
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Performing LDAP compare of password attribute '" + passwordAttributeName + "' for user '"
					+ user.getDn() + "'");
		}

		if (usePasswordAttrCompare && isPasswordAttrCompare(user, password)) {
			return user;
		}
		else if (isLdapPasswordCompare(user, ldapTemplate, password)) {
			return user;
		}
		throw new BadCredentialsException(
				messages.getMessage("PasswordComparisonAuthenticator.badCredentials", "Bad credentials"));
	}

	private boolean isPasswordAttrCompare(DirContextOperations user, String password) {
		String passwordAttrValue = getPassword(user);
		return passwordEncoder.matches(password, passwordAttrValue);
	}

	private String getPassword(DirContextOperations user) {
		Object passwordAttrValue = user.getObjectAttribute(this.passwordAttributeName);
		if (passwordAttrValue == null) {
			return null;
		}
		if (passwordAttrValue instanceof byte[]) {
			return new String((byte[]) passwordAttrValue);
		}
		return String.valueOf(passwordAttrValue);
	}

	private boolean isLdapPasswordCompare(DirContextOperations user, SpringSecurityLdapTemplate ldapTemplate,
			String password) {
		String encodedPassword = passwordEncoder.encode(password);
		byte[] passwordBytes = Utf8.encode(encodedPassword);
		return ldapTemplate.compare(user.getDn().toString(), passwordAttributeName, passwordBytes);
	}

	public void setPasswordAttributeName(String passwordAttribute) {
		Assert.hasLength(passwordAttribute, "passwordAttributeName must not be empty or null");
		this.passwordAttributeName = passwordAttribute;
	}

	public void setUsePasswordAttrCompare(boolean usePasswordAttrCompare) {
		this.usePasswordAttrCompare = usePasswordAttrCompare;
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder must not be null.");
		this.passwordEncoder = passwordEncoder;
		setUsePasswordAttrCompare(true);
	}

}
