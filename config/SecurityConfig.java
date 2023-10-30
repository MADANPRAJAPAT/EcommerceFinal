
package com.coder.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.coder.services.CustomUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	private CustomAuthSuccessHandler successHandler;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService getDetailsService() {
		return new CustomUserDetailsService();
	}
	
	@Bean
	public DaoAuthenticationProvider getAuthenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider=new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(getDetailsService());
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		return daoAuthenticationProvider;
	}

	 @Bean
	    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	        http
	            .authorizeHttpRequests((authz) -> authz
	            	    .requestMatchers("/","/shop","/register","/search/**").permitAll()
	                    .requestMatchers("/admin/**").hasRole("ADMIN")
	                    .anyRequest().authenticated()
	            )
	            .formLogin(formLogin ->
	            formLogin
	              .loginPage("/login")
	                .permitAll()
	                .failureUrl("/login?error=true")
	                .defaultSuccessUrl("/")
	                .usernameParameter("email")
	                .passwordParameter("password")
	          )
// 	        .oauth2Login(oauth2Login ->
//               oauth2Login
//                   .loginPage("/login")
//                   .successHandler(googleOAuth2SuccessHandler())
	     //   )
	        .logout(logout ->
	            logout
	                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	                .logoutSuccessUrl("/login")
	                .invalidateHttpSession(true)
	                .deleteCookies("JSESSIONID")
	        )
	        .exceptionHandling()
	        .and()
	        .csrf()
	        .disable();
	
	     return http.build();
	    
	    }
	 
	
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
	    return (web) -> web.ignoring()
	        .requestMatchers("/resources/**")
	        .requestMatchers("/static/**")
	        .requestMatchers("/images/**")
	        .requestMatchers("/productImages/**")
	        .requestMatchers("/css/**")
	        .requestMatchers("/js/**");
	}  


}



