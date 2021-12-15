package sample.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoopbackIpRedirectFilter extends OncePerRequestFilter {

    final static Logger logger = LoggerFactory.getLogger(LoopbackIpRedirectFilter.class);

//	public String[] logoutToken = new String[]{ "", "", "", "", "", "", "", "", "", ""};

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("================LoopbackIpRedirectFilter : "
                + request.getMethod() + " "
                + request.getRequestURI()
                + ( request.getQueryString() != null ? "?" + request.getQueryString() : "" ));
// http://127.0.0.1:8080/oauth2/authorization/messaging-client-oidc
// http://auth-server:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid&state=gUyAarzVKXvdgwtU-rNDLLzXLxcX9v2rJ7u1J2i4KgI%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&nonce=-IqKg5M82fxC2Fuw4kRDRVGZDbITo-4NQNwpR5X8Gnw

//		authorization 에서 로그아웃 할 경우 토큰에 대한 관리가 필요 없어졌다 .
//		System.out.println("============================");
//		System.out.println("======logout : " + isLogoutToken(request.getHeader("authorization")));
//		System.out.println("============================");
//		if( request.getRequestURI().equals("/messages/logout") ){
//			putToken(request.getHeader("authorization"));
//			response.sendRedirect("http://127.0.0.1:8080/oauth2/authorization/messaging-client-oidc");
//		}

        filterChain.doFilter(request, response);
    }

/*
	public boolean isLogoutToken(String token){
		for (String s : logoutToken) {
			if(s.equals(token))
				return true;
		}
		return false;
	}

	public void putToken(String token){
		for( int i = 0 ; i < logoutToken.length ; i++ ){
			if( logoutToken[i] == null || logoutToken[i].equals("")) {
				logoutToken[i] = token;
				break;
			}
		}
	}

 */
}
