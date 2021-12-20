/*
 * Copyright 2020 the original author or authors.
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
package sample.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import sample.MessagesResourceApplication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@RestController
public class MessagesController {

	final static Logger logger = LoggerFactory.getLogger(MessagesController.class);

	@GetMapping("/messages")
	public String[] getMessages(
			@AuthenticationPrincipal Jwt jwt
			, HttpServletRequest request
			, HttpServletResponse response) {
		Enumeration<String> headerNames = request.getHeaderNames();
		System.out.println("============================");
		while(headerNames.hasMoreElements()){
			String name = headerNames.nextElement();
			System.out.println(name + " : " + request.getHeader(name));
		}
		System.out.println(" jwt.getTokenValue() : " + jwt.getTokenValue() );
		return new String[] {"Message 1", "Message 2", "Message 3"};
	}

	// authorization 에서 로그아웃이 되어 있지 않으면 재요청으로 자동 로그인 된다.
	// 관련하여 authorization 에서도 로그아웃 하도록 처리 한다.
	// WebClient 에서 배열을 리턴 받고 있어 배열로 리턴 한다.
	@GetMapping("/messages/logout")
	public String[] logout() {
		return new String[] {"redirect:http://auth-server:9000/logout"};
	}
}
