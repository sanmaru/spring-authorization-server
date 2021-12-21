package sample.multifactor;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collection;

import static java.util.stream.Collectors.joining;

@Controller
public class MultiFactorController {

	final static Logger logger = LoggerFactory.getLogger(MultiFactorController.class);

	@GetMapping( value="/login/multifactor")
	public String GetMultifactor(){
		Collection<? extends GrantedAuthority> authorities  = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
		logger.info( "logger info" + authorities.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(joining("\n  ")));
		logger.info("GetMultifactor");
		return "multifactor";
	}

	@PostMapping( value="/login/multifactor")
	public String PostMultifactor(HttpServletRequest request, HttpServletResponse response) {
		logger.info("PostMultifactor");
		HttpSession session = request.getSession();
		logger.info( "referer : " + session.getAttribute("referer") );
		return "redirect:"+ (session.getAttribute("referer")!=null?session.getAttribute("referer"):"/");
	}
}
