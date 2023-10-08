package ca.sheridancollege.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    LoggingAccessDeniedHandler accessDeniedHandler;

    @Autowired
    public void setAccessDeniedHandler(LoggingAccessDeniedHandler accessDeniedHandler){
        this.accessDeniedHandler = accessDeniedHandler;
    }
    private String IDENTITY_MANAGER = "Manager";// this Manager and "User" value is passed in gateway after ROLE_Manager or ROLE_User
    private String IDENTITY_USER = "User";
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/user/**").hasAnyRole(IDENTITY_USER, IDENTITY_MANAGER)
                .antMatchers("/secure/**").hasAnyRole(IDENTITY_USER, IDENTITY_MANAGER)
                .antMatchers("/manager/**").hasRole(IDENTITY_MANAGER)
                .antMatchers("/","/**","/logout.html","/logoutSuccess.html").permitAll()
                .and()
                .formLogin().loginPage("/login")
                .defaultSuccessUrl("/secured")
                .and().logout()
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/")
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .and()
                .csrf().disable()
                .exceptionHandling().accessDeniedPage("/error")
                ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                .withUser("bugs").password("bunny").roles(IDENTITY_USER)
                .and()
                .withUser("looney").password("tunes").roles(IDENTITY_USER,IDENTITY_MANAGER);
    }
}
