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

import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import sample.mfa.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

	@Bean
	SecurityFilterChain web(HttpSecurity http,
			AuthorizationManager<RequestAuthorizationContext> mfaAuthorizationManager) throws Exception {
		MfaAuthenticationHandler mfaAuthenticationHandler = new MfaAuthenticationHandler("/second-factor");
		// @formatter:off
		http
				.authorizeHttpRequests((authorize) -> authorize
						.mvcMatchers("/second-factor", "/third-factor").access(mfaAuthorizationManager)
						.anyRequest().authenticated()
				)
				.formLogin((form) -> form
						.successHandler(mfaAuthenticationHandler)
						.failureHandler(mfaAuthenticationHandler)
				)
				.exceptionHandling((exceptions) -> exceptions
						.withObjectPostProcessor(new ObjectPostProcessor<ExceptionTranslationFilter>() {
							@Override
							public <O extends ExceptionTranslationFilter> O postProcess(O filter) {
								filter.setAuthenticationTrustResolver(new MfaTrustResolver());
								return filter;
							}
						})
				);
		// @formatter:on
		return http.build();
	}

	// @formatter:off
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests(authorizeRequests ->
//				authorizeRequests.antMatchers("/second-factor", "/third-factor").anonymous()
				authorizeRequests.mvcMatchers("/second-factor", "/third-factor").anonymous()
						.anyRequest().authenticated()
			)
			.formLogin(withDefaults())
			.logout()
//				.logoutSuccessUrl("http://127.0.0.1:8080/oauth2/authorization/messaging-client-oidc");
				.logoutSuccessUrl("http://127.0.0.1:8080/");
		return http.build();
	}
	// @formatter:on

	// @formatter:off
	/* MapCustomUserRepository로 교체
	@Bean
	UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	 */
	// @formatter:on
	// for the second-factor
	@Bean
	AesBytesEncryptor encryptor() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128);
		SecretKey key = generator.generateKey();
		return new AesBytesEncryptor(key, KeyGenerators.secureRandom(12), AesBytesEncryptor.CipherAlgorithm.GCM);
	}

	@Bean
	AuthorizationManager<RequestAuthorizationContext> mfaAuthorizationManager() {
		return (authentication,
				context) -> new AuthorizationDecision(authentication.get() instanceof MfaAuthentication);
	}

	// for the third-factor
	@Bean
	PasswordEncoder encoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	AuthenticationSuccessHandler successHandler() {
		return new SavedRequestAwareAuthenticationSuccessHandler();
	}

	@Bean
	AuthenticationFailureHandler failureHandler() {
		return new SimpleUrlAuthenticationFailureHandler("/login?error");
	}

	@Bean
	MapCustomUserRepository userRepository(BytesEncryptor encryptor) {
		// the hashed password was calculated using the following code
		// the hash should be done up front, so malicious users cannot discover the
		// password
		// PasswordEncoder encoder =
		// PasswordEncoderFactories.createDelegatingPasswordEncoder();
		// String encodedPassword = encoder.encode("password");

		// the raw password is "password"
		String encodedPassword = "{bcrypt}$2a$10$h/AJueu7Xt9yh3qYuAXtk.WZJ544Uc2kdOKlHu2qQzCh/A3rq46qm";

		// to sync your phone with the Google Authenticator secret, hand enter the value
		// in base32Key
		// String base32Key = "QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK";
		// Base32 base32 = new Base32();
		// byte[] b = base32.decode(base32Key);
		// String secret = Hex.encodeHexString(b);

		String hexSecret = "80ed266dd80bcd32564f0f4aaa8d9b149a2b1eaa";
		String encrypted = new String(Hex.encode(encryptor.encrypt(hexSecret.getBytes())));

		// the raw security answer is "smith"
		String encodedSecurityAnswer = "{bcrypt}$2a$10$JIXMjAszy3RUu8y5T0zH0enGJCGumI8YE.K7w3wsM5xXDfeVIsJhq";

		CustomUser customUser = new CustomUser(1L, "user", encodedPassword, encrypted,
				encodedSecurityAnswer);
		Map<String, CustomUser> emailToCustomUser = new HashMap<>();
		emailToCustomUser.put(customUser.getEmail(), customUser);
		return new MapCustomUserRepository(emailToCustomUser);
	}

}
