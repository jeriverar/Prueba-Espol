/*
 * Copyright 2002-2019 the original author or authors.
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

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2TokenIntrospectionClient;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s,
 * using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
 * to check the token's validity and reveal its attributes.
 * <p>
 * This {@link AuthenticationProvider} is responsible for introspecting and verifying an opaque access token,
 * returning its attributes set as part of the {@see Authentication} statement.
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following algorithm:
 * <ol>
 * <li>
 * If there is a "scope" attribute, then convert to a {@link Collection} of {@link String}s.
 * <li>
 * Take the resulting {@link Collection} and prepend the "SCOPE_" keyword to each element, adding as {@link GrantedAuthority}s.
 * </ol>
 *
 * @author Josh Cummings
 * @since 5.2
 * @see AuthenticationProvider
 */
public final class OAuth2IntrospectionAuthenticationProvider implements AuthenticationProvider {
	private static final BearerTokenError DEFAULT_INVALID_TOKEN =
			invalidToken("An error occurred while attempting to introspect the token: Invalid token");

	private OAuth2TokenIntrospectionClient introspectionClient;
	
	private Converter<IntrospectionOAuth2Token, ? extends AbstractAuthenticationToken> authenticationConverter;

	/**
	 * Creates a {@code OAuth2IntrospectionAuthenticationProvider} with the provided parameters
	 *
	 * @param introspectionClient The {@link OAuth2TokenIntrospectionClient} to use
	 */
	public OAuth2IntrospectionAuthenticationProvider(OAuth2TokenIntrospectionClient introspectionClient) {
		Assert.notNull(introspectionClient, "introspectionClient cannot be null");
		this.introspectionClient = introspectionClient;
	}
	
	public OAuth2IntrospectionAuthenticationProvider setAuthenticationConverter(
			Converter<IntrospectionOAuth2Token, ? extends AbstractAuthenticationToken> authenticationConverter) {
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Introspect and validate the opaque
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
	 *
	 * @param authentication the authentication request object.
	 *
	 * @return A successful authentication
	 * @throws AuthenticationException if authentication failed for some reason
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof BearerTokenAuthenticationToken)) {
			return null;
		}
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

		Map<String, Object> claims;
		try {
			claims = this.introspectionClient.introspect(bearer.getToken());
		} catch (OAuth2IntrospectionException failed) {
			OAuth2Error invalidToken = invalidToken(failed.getMessage());
			throw new OAuth2AuthenticationException(invalidToken);
		}

		AbstractAuthenticationToken result = authenticationConverter.convert(new IntrospectionOAuth2Token(bearer.getToken(), claims));
		result.setDetails(bearer.getDetails());
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static BearerTokenError invalidToken(String message) {
		try {
			return new BearerTokenError("invalid_token",
					HttpStatus.UNAUTHORIZED, message,
					"https://tools.ietf.org/html/rfc7662#section-2.2");
		} catch (IllegalArgumentException malformed) {
			// some third-party library error messages are not suitable for RFC 6750's error message charset
			return DEFAULT_INVALID_TOKEN;
		}
	}
	
	public static class ScopeClaimAuthoritiesConverter implements Converter<Map<String, Object>, Collection<GrantedAuthority>> {
		@Override
		public Collection<GrantedAuthority> convert(Map<String, Object> claims) {
			final Object scopesClaim = claims.get(SCOPE);
			final Stream<String> scopes;
			if(scopesClaim instanceof String) {
				//As of RFC-6749: The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings
				scopes = Stream.of(scopesClaim.toString().split(" "));
			} else if(scopesClaim instanceof Collection) {
				//Backward compatibility
				scopes = ((Collection<?>) scopesClaim).stream().map(Object::toString);
			} else {
				scopes = Stream.empty();
			}
			return scopes.map(authority -> new SimpleGrantedAuthority("SCOPE_" + authority))
					.collect(Collectors.toList());
		}
	}
	
	public static class IntrospectionOAuth2Token extends AbstractOAuth2Token implements ClaimAccessor {
		private final Map<String, Object> claims;

		public IntrospectionOAuth2Token(String tokenValue, Map<String, Object> claims) {
			super(
					tokenValue,
					new SimpleClaimAccessor(claims).getClaimAsInstant(ISSUED_AT),
					new SimpleClaimAccessor(claims).getClaimAsInstant(EXPIRES_AT));
			this.claims = claims;
		}

		@Override
		public Map<String, Object> getClaims() {
			return claims;
		}
		
		private static class SimpleClaimAccessor implements ClaimAccessor {
			private final Map<String, Object> claims;

			public SimpleClaimAccessor(Map<String, Object> claims) {
				this.claims = claims;
			}

			@Override
			public Map<String, Object> getClaims() {
				return claims;
			}
			
		}
		
	}
}
