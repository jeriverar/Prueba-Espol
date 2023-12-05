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

package org.springframework.security.config.annotation.method.configuration;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationEventPublisher;
import org.springframework.security.authorization.event.ReactiveAuthorizationDeniedEvent;
import org.springframework.security.authorization.event.ReactiveAuthorizationEvent;
import org.springframework.security.authorization.event.ReactiveAuthorizationGrantedEvent;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.test.context.support.ReactorContextTestExecutionListener;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@TestExecutionListeners(
		listeners = { WithSecurityContextTestExecutionListener.class, ReactorContextTestExecutionListener.class })
public class ReactiveAuthorizationManagerMethodSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	ReactiveMessageService messageService;

	@Autowired
	ReactiveAuthorizationEventPublisher eventPublisher;

	@Autowired
	MyEventListener eventListener;

	AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();

	@Test
	void preAuthorizeMonoWhenDeniedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.monoPreAuthorizeHasRoleFindById(1))
			.expectError(AccessDeniedException.class)
			.verify();
		ReactiveAuthorizationDeniedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isFalse();
		StepVerifier.create(event.getAuthentication()).assertNext(this.trustResolver::isAnonymous).verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void preAuthorizeMonoWhenGrantedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.monoPreAuthorizeHasRoleFindById(1)).verifyComplete();
		ReactiveAuthorizationGrantedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isTrue();
		StepVerifier.create(event.getAuthentication())
			.assertNext((auth) -> assertThat(auth.getAuthorities()).extracting(GrantedAuthority::getAuthority)
				.contains("ROLE_ADMIN"))
			.verifyComplete();
	}

	@Test
	void preAuthorizeFluxWhenDeniedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.fluxPreAuthorizeHasRoleFindById(1))
			.expectError(AccessDeniedException.class)
			.verify();
		ReactiveAuthorizationDeniedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isFalse();
		StepVerifier.create(event.getAuthentication()).assertNext(this.trustResolver::isAnonymous).verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void preAuthorizeFluxWhenGrantedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.fluxPreAuthorizeHasRoleFindById(1)).verifyComplete();
		ReactiveAuthorizationGrantedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isTrue();
		StepVerifier.create(event.getAuthentication())
			.assertNext((auth) -> assertThat(auth.getAuthorities()).extracting(GrantedAuthority::getAuthority)
				.contains("ROLE_ADMIN"))
			.verifyComplete();
	}

	@Test
	void postAuthorizeMonoWhenDeniedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.monoPostAuthorizeFindById(1))
			.expectError(AccessDeniedException.class)
			.verify();
		ReactiveAuthorizationDeniedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isFalse();
		StepVerifier.create(event.getAuthentication()).assertNext(this.trustResolver::isAnonymous).verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void postAuthorizeMonoWhenGrantedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.monoPostAuthorizeFindById(1)).expectNext("user").verifyComplete();
		ReactiveAuthorizationGrantedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isTrue();
		StepVerifier.create(event.getAuthentication())
			.assertNext((auth) -> assertThat(auth.getAuthorities()).extracting(GrantedAuthority::getAuthority)
				.contains("ROLE_ADMIN"))
			.verifyComplete();
	}

	@Test
	@WithMockUser(username = "notuser")
	void postAuthorizeFluxWhenDeniedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.fluxPostAuthorizeFindById(1))
			.expectError(AccessDeniedException.class)
			.verify();
		ReactiveAuthorizationDeniedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isFalse();
		StepVerifier.create(event.getAuthentication()).assertNext(this.trustResolver::isAnonymous).verifyComplete();
	}

	@Test
	@WithMockUser
	void postAuthorizeFluxWhenGrantedThenPublishEvent() {
		this.spring.register(Config.class, AuthorizationEventPublisherConfig.class).autowire();
		StepVerifier.create(this.messageService.fluxPostAuthorizeFindById(1)).expectNext("user").verifyComplete();
		ReactiveAuthorizationGrantedEvent<?> event = this.eventListener.getEvent();
		assertThat(event).isNotNull();
		assertThat(event.getAuthorizationDecision().isGranted()).isTrue();
		StepVerifier.create(event.getAuthentication()).expectNextCount(1).verifyComplete();
	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class Config {

		@Bean
		DelegatingReactiveMessageService defaultMessageService() {
			return new DelegatingReactiveMessageService(new StubReactiveMessageService());
		}

		@Bean
		Authz authz() {
			return new Authz();
		}

	}

	@Configuration
	static class AuthorizationEventPublisherConfig {

		@Bean
		ReactiveAuthorizationEventPublisher authorizationEventPublisher(ApplicationEventPublisher eventPublisher) {
			return new ReactiveAuthorizationEventPublisher() {
				@Override
				public <T> void publishAuthorizationEvent(Mono<Authentication> authentication, T object,
						AuthorizationDecision decision) {
					ReactiveAuthorizationEvent event;
					if (decision.isGranted()) {
						event = new ReactiveAuthorizationGrantedEvent<>(authentication, object, decision);
					}
					else {
						event = new ReactiveAuthorizationDeniedEvent<>(authentication, object, decision);
					}
					eventPublisher.publishEvent(event);
				}
			};
		}

		@Bean
		MyEventListener myEventListener() {
			return new MyEventListener();
		}

	}

	public static class MyEventListener implements ApplicationListener<ReactiveAuthorizationEvent> {

		static BlockingQueue<ReactiveAuthorizationEvent> events = new ArrayBlockingQueue<>(10);

		public <T extends ReactiveAuthorizationEvent> T getEvent() {
			try {
				return (T) events.poll(1, TimeUnit.SECONDS);
			}
			catch (InterruptedException ex) {
				return null;
			}
		}

		@Override
		public void onApplicationEvent(ReactiveAuthorizationEvent event) {
			events.add(event);
		}

	}

}
