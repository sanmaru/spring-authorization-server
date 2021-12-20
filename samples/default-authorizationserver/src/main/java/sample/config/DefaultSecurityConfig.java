/*
 * Copyright 2020-2021 the original author or authors.
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
package sample.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import sample.multifactor.MultiFactorAuthenticationSuccessHandler;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

	final static Logger logger = LoggerFactory.getLogger(DefaultSecurityConfig.class);

	// @formatter:off
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		MultiFactorAuthenticationSuccessHandler multiFactorAuthenticationHandler = new MultiFactorAuthenticationSuccessHandler();

		http
			.authorizeRequests(authorizeRequests ->
				authorizeRequests
						.antMatchers("/login/multifactor").hasAuthority("ROLE_TOTP")
						.antMatchers("/login","/login/**").permitAll()
						.anyRequest().authenticated()
			)
			.formLogin(withDefaults())
			.formLogin( (form) -> form
					.successHandler(multiFactorAuthenticationHandler)
			)
			.logout()
//				.logoutSuccessUrl("http://127.0.0.1:8080/oauth2/authorization/messaging-client-oidc");
				.logoutSuccessUrl("http://127.0.0.1:8080/");
		return http.build();
	}
	// @formatter:on

	// @formatter:off

	@Bean
	UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.roles("TOTP")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	/*
	@Bean
	UserDetailsService users(DataSource dataSource) {
		UserDetails user = User.builder().username("user")
				.password("{bcrypt}$2a$10$AiyMWI4UBLozgXq6itzyVuxrtofjcPzn/WS3fOrcqgzdax9jB7Io.").roles("USER").build();
		UserDetails admin = User.builder().username("admin")
				.password("{bcrypt}$2a$10$AiyMWI4UBLozgXq6itzyVuxrtofjcPzn/WS3fOrcqgzdax9jB7Io.").roles("USER", "ADMIN")
				.build();
		JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
		users.createUser(user);
		users.createUser(admin);
		return users;
	}

	 */
	// @formatter:on


}
