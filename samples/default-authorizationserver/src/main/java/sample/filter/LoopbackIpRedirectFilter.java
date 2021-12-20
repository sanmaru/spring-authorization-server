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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
		/* URL 호출에 대한 로그 출력 */
        logger.info("===LoopbackIpRedirectFilter : "
                + request.getMethod() + " "
                + request.getRequestURI()
                + ( request.getQueryString() != null ? "?" + request.getQueryString() : "" ));

		/* Login 요청이 왔을 때 권한 체크를 진행한 Login요청 경로를 세션에 저장 */
		if (request.getRequestURI().equals("/oauth2/authorize")){
			logger.info("===LoopbackIpRedirectFilter : save referer on session");
			request.getSession().setAttribute("referer", request.getRequestURI() + ( request.getQueryString() != null ? "?" + request.getQueryString() : ""));
		}

        filterChain.doFilter(request, response);
    }

}
