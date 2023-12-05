/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.authorization.event;

import reactor.core.publisher.Mono;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

public class ReactiveAuthorizationGrantedEvent<T> extends ReactiveAuthorizationEvent {

	/**
	 * Construct an {@link ReactiveAuthorizationGrantedEvent}
	 * @param authentication the principal requiring access
	 * @param object the object to which access was requested
	 * @param decision whether authorization was granted or denied
	 */
	public ReactiveAuthorizationGrantedEvent(Mono<Authentication> authentication, Object object,
			AuthorizationDecision decision) {
		super(authentication, object, decision);
	}

	@Override
	@SuppressWarnings("unchecked")
	public T getObject() {
		return (T) getSource();
	}

}
