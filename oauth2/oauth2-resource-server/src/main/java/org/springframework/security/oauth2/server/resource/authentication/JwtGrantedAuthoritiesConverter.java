/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a
 * {@link Jwt}.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @author Eric Deandrea
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public final class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	private static final String DEFAULT_AUTHORITIES_PREFIX = "SCOPE_";

	private static final Set<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Stream.of("scope", "scp").collect(Collectors.toSet());
	
	private String prefix;
	private Set<String> authoritiesAttributeNames;

	public JwtGrantedAuthoritiesConverter(String prefix, Collection<String> authoritiesAttributeNames) {
		super();
		this.prefix = prefix;
		this.authoritiesAttributeNames = new HashSet<>(authoritiesAttributeNames);
	}
	
	public JwtGrantedAuthoritiesConverter() {
		this(DEFAULT_AUTHORITIES_PREFIX, WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES);
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public void setAuthoritiesAttributeNames(String... authoritiesAttributeNames) {
		this.authoritiesAttributeNames = Set.of(authoritiesAttributeNames);
	}

	public void setAuthoritiesAttributeNames(Collection<String> authoritiesAttributeNames) {
		this.authoritiesAttributeNames = authoritiesAttributeNames.stream().collect(Collectors.toSet());
	}

	/**
	 * Extracts the authorities
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		return authoritiesAttributeNames.stream()
				.flatMap(claimName -> getAuthorities(jwt, claimName))
				.map(authority -> prefix + authority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

	@SuppressWarnings("unchecked")
	private Stream<String> getAuthorities(Jwt jwt, String claimName) {
		Object authorities = jwt.getClaim(claimName);
		if (authorities instanceof String) {
			if (StringUtils.hasText((String) authorities)) {
				return Stream.of(((String) authorities).split(" "));
			} else {
				return Stream.empty();
			}
		} else if (authorities instanceof Collection) {
			return ((Collection<String>) authorities).stream();
		}

		return Stream.empty();
	}
}
