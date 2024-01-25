/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.List;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.core.annotation.MergedAnnotations.SearchStrategy;
import org.springframework.core.annotation.RepeatableContainers;

/**
 * A collection of utility methods that check for, and error on, conflicting annotations.
 * This is specifically important for Spring Security annotations which are not designed
 * to be repeatable.
 *
 * <p>
 * There are numerous ways that two annotations of the same type may be attached to the
 * same method. For example, a class may implement a method defined in two separate
 * interfaces. If both of those interfaces have a {@code @PreAuthorize} annotation, then
 * it's unclear which {@code @PreAuthorize} expression Spring Security should use.
 *
 * <p>
 * Another way is when one of Spring Security's annotations is used as a meta-annotation.
 * In that case, two custom annotations can be declared, each with their own
 * {@code @PreAuthorize} declaration. If both custom annotations are used on the same
 * method, then it's unclear which {@code @PreAuthorize} expression Spring Security should
 * use.
 *
 * @author Josh Cummings
 * @author Sam Brannen
 * @author DingHao
 */
final class AuthorizationAnnotationUtils {

	/**
	 * Perform an exhaustive search on the type hierarchy of the given {@link Method} for
	 * the annotation of type {@code annotationType}, including any annotations using
	 * {@code annotationType} as a meta-annotation.
	 *
	 * <p>
	 * If more than one unique annotation is found, then throw an error.
	 * @param method the method declaration to search from
	 * @param annotationType the annotation type to search for
	 * @return a unique instance of the annotation attributed to the method, {@code null}
	 * otherwise
	 * @throws AnnotationConfigurationException if more than one unique instance of the
	 * annotation is found
	 */
	static <A extends Annotation> A findUniqueAnnotation(Method method, Class<A> annotationType) {
		return findDistinctAnnotation(method, annotationType);
	}

	/**
	 * Perform an exhaustive search on the type hierarchy of the given {@link Class} for
	 * the annotation of type {@code annotationType}, including any annotations using
	 * {@code annotationType} as a meta-annotation.
	 *
	 * <p>
	 * If more than one unique annotation is found, then throw an error.
	 * @param type the type to search from
	 * @param annotationType the annotation type to search for
	 * @return a unique instance of the annotation attributed to the class, {@code null}
	 * otherwise
	 * @throws AnnotationConfigurationException if more than one unique instance of the
	 * annotation is found
	 */
	static <A extends Annotation> A findUniqueAnnotation(Class<?> type, Class<A> annotationType) {
		return findDistinctAnnotation(type, annotationType);
	}

	private static <A extends Annotation> A findDistinctAnnotation(AnnotatedElement annotatedElement,
			Class<A> annotationType) {
		MergedAnnotations mergedAnnotations = MergedAnnotations.from(annotatedElement, SearchStrategy.TYPE_HIERARCHY,
				RepeatableContainers.none());

		List<A> annotations = mergedAnnotations.stream(annotationType)
			.map(MergedAnnotation::withNonMergedAttributes)
			.map(MergedAnnotation::synthesize)
			.distinct()
			.toList();

		return switch (annotations.size()) {
			case 0 -> null;
			case 1 -> annotations.get(0);
			default -> throw new AnnotationConfigurationException("""
					Please ensure there is one unique annotation of type @%s attributed to %s. \
					Found %d competing annotations: %s""".formatted(annotationType.getName(), annotatedElement,
					annotations.size(), annotations));
		};
	}

	static <A extends Annotation> MergedAnnotation<A> findUniqueMergedAnnotation(AnnotatedElement annotatedElement,
			Class<A> annotationType) {
		MergedAnnotations mergedAnnotations = MergedAnnotations.from(annotatedElement,
				MergedAnnotations.SearchStrategy.TYPE_HIERARCHY, RepeatableContainers.none());

		List<MergedAnnotation<A>> annotations = mergedAnnotations.stream(annotationType)
			.map(MergedAnnotation::withNonMergedAttributes)
			.distinct()
			.toList();

		return switch (annotations.size()) {
			case 0 -> null;
			case 1 -> annotations.get(0);
			default -> throw new AnnotationConfigurationException("""
					Please ensure there is one unique annotation of type @%s attributed to %s. \
					Found %d competing annotations: %s""".formatted(annotationType.getName(), annotatedElement,
					annotations.size(), annotations));
		};
	}

	private AuthorizationAnnotationUtils() {

	}

}
