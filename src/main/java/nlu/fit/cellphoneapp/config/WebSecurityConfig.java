package nlu.fit.cellphoneapp.config;

import nlu.fit.cellphoneapp.others.BcryptEncoder;
import nlu.fit.cellphoneapp.security.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Autowired
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    @Autowired
    private UserDetailService userDetailService;
    @Autowired
    private MyAccessDeniedHandler myAccessDeniedHandler;
    @Autowired
    private MyForbiddenEntryPoint myForbiddenEntryPoint;

    private static final String[] PUBLIC_MATCHERS = {
            "/fontawesome/**",
            "/admin-component/**",
            "/admin-static/**",
            "/cart/**",
            "/login",
            "/product/**",
            "/webjars/**",
            "/css/**",
            "/js/**",
            "/images/**",
            "/",
            "/home",
            "/index",
            "/about/**",
            "/contact/**",
            "/error/**/*",
            "/console/**",
            "/register",
            "/home",
            "/forgot-pass",
            "/reset-pass",
            "/signup",
            "/add-to-cart",
            "/checkout",
            "/cart/delete",
            "/order",
            "/api/**",
            "/ckeditor/**",
            "/unblock-account"

    };

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(PUBLIC_MATCHERS).permitAll()
                .antMatchers("/user/**").hasAnyAuthority("USER","ADMIN")
                .antMatchers("/admin/**").hasAuthority("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login").permitAll()
                .loginPage("/").permitAll()
                .usernameParameter("email")
                .passwordParameter("password")
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .deleteCookies("remember-me", "JSESSIONID")
                .permitAll()
                .and()
                .exceptionHandling().accessDeniedHandler(myAccessDeniedHandler)
                .and().exceptionHandling().authenticationEntryPoint(myForbiddenEntryPoint)
                .and()
                .rememberMe().key("uniqueAndSecret").and().csrf().disable().cors();
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailService)
                .passwordEncoder(BcryptEncoder.getInstance());
    }
}
