package boot.application.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeRequests().antMatchers("/").permitAll()//allow all requests to the root url ("/")
				.and().authorizeRequests().antMatchers("/console/**").permitAll(); //allow all requests to the H2 database console url ("/console/")

		httpSecurity.csrf().disable(); //disable default Spring Security CSRF protection
		httpSecurity.headers().frameOptions().disable(); //disable default X-Frame-Options in Spring Security
	}
}
