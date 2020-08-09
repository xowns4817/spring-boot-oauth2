package com.example.oauth.demo.security;

import com.example.oauth.demo.service.CustomOAuth2UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.example.oauth.demo.security.SocialType.*;

/**
 *   .antMatchers 메서드를 이용해 매칭되는 url를 정의함. /facebook, /google URL에서는 권한이 있을때만 URL 접근 허용
 *
 *
 */
@Configuration
@EnableWebSecurity // spring security 설정을 활성화 시켜줌
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests()// url 별 권한 관리를 설정하는 옵션의 시작점. 이게 선언되어야 antMatchers  옵션을 사용할 수 있음.
                .antMatchers("/", "/oauth2/**", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**", "/favicon.ico/**")
                .permitAll() // 위에 있는 경로는 누구나 접근 가능
                .antMatchers("/google").hasAuthority(GOOGLE.getRoleType()) // 관리 대상을 지정하는 옵션. google, facebook, naver는 role을 가지고 있어야만 접근가능. 즉, 인증된 사용자만 가능
                .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
                .antMatchers("/naver").hasAuthority(NAVER.getRoleType())
                .antMatchers("/github").hasAnyAuthority(GITHUB.getRoleType())
                .anyRequest().authenticated() // anyRequest( )는 위에서 설정한 것 외의 나머지 경로를 뜻함. authenticated() 메소드를 호출하여 인증된 사용자만 접근 하도록 함. ( 로그인된 사용자 )
                .and()
                .oauth2Login() // OAuth2 로그인에 대한 여러 설정의 진입점.
                .userInfoEndpoint().userService(new CustomOAuth2UserService()) // 네이버 USER INFO의 응답을 처리하기 위한 설정 ( userInfoEndPoint -> OAuth2 로그인 성공 후 사용자 정보를 가져올 때의 설정 )
                .and()
                .defaultSuccessUrl("/loginSuccess") // 성공시 redirect 될 url
                .failureUrl("/loginFailure") // 실패시 redirect 될 url
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
    }
}
