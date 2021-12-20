package sample.multifactor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MultiFactorAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	final static Logger logger = LoggerFactory.getLogger(MultiFactorAuthenticationSuccessHandler.class);


	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
		logger.info("==== MultiFactorAuthenticationHandler.onAuthenticationSuccess ");
		AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//		Id/Password 가 성공하였을 때 Multifactor 인증을 받는다.
		logger.info("=== MultiFactorAuthenticationHandler.onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) ");
		response.sendRedirect("/login/multifactor");

	}
}
