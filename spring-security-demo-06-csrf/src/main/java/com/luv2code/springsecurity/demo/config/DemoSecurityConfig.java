package com.luv2code.springsecurity.demo.config;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;


@Configurable
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		UserBuilder users = User.withDefaultPasswordEncoder();
		auth.inMemoryAuthentication().withUser(users.username("john").password("test123").roles("ADMIN"));
		auth.inMemoryAuthentication().withUser(users.username("kiran").password("test123").roles("MANAGER"));
		auth.inMemoryAuthentication().withUser(users.username("mahesh").password("test123").roles("EMPLOYEE"));
	
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	
		http.authorizeRequests()
			.anyRequest().authenticated().and()
			.formLogin().loginPage("/showLoginPage")
			.loginProcessingUrl("/authonticateTheUser").permitAll()
			.and().logout().permitAll();
	}
}
