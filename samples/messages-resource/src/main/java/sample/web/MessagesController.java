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

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@RestController
public class MessagesController {

	@GetMapping("/messages")
	public String[] getMessages(HttpServletRequest request, HttpServletResponse response) {
		Enumeration<String> headerNames = request.getHeaderNames();
		System.out.println("============================");
		while(headerNames.hasMoreElements()){
			String name = headerNames.nextElement();
			System.out.println(name + " : " + request.getHeader(name));
		}
		System.out.println("============================");
		return new String[] {"Message 1", "Message 2", "Message 3"};
	}
}
