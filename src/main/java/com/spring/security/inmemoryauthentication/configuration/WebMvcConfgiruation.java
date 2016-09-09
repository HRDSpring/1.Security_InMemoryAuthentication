package com.spring.security.inmemoryauthentication.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class WebMvcConfgiruation extends WebMvcConfigurerAdapter {

	
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		// TODO Auto-generated method stub
		registry.addViewController("/").setViewName("home");
		registry.addViewController("/home").setViewName("home");
		
		registry.addViewController("/about").setViewName("about");
		registry.addViewController("/db").setViewName("/db/db");
		registry.addViewController("/admin").setViewName("/admin/admin");
		registry.addViewController("/user").setViewName("/user/user");
		registry.addViewController("/access-denied").setViewName("/error/access-denied");
	}
	
	
}
