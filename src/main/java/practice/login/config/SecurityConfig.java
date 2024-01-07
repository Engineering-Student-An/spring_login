package practice.login.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import practice.login.domain.MemberRole;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 시큐리티 필터 메서드
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/security-login", "/security-login/login", "/security-login/join").permitAll()
                        .requestMatchers("/security-login/admin").hasRole(MemberRole.ADMIN.name())
                        .requestMatchers("/security-login/info").hasAnyRole(MemberRole.ADMIN.name(), MemberRole.USER.name())
                        .anyRequest().authenticated()
                );

        http
                .logout((auth) -> auth
                        .logoutUrl("/security-login/logout")
                );

        http
                .formLogin((auth) -> auth.loginPage("/security-login/login")
                        .loginProcessingUrl("/security-login/loginProc")
                        // 프론트단에서 설정해 둔 경로로 로그인 정보를 넘기면 스프링 시큐리티가 받아서 자동으로 로그인 진행
                        .failureUrl("/security-login/login")
                        .defaultSuccessUrl("/security-login")
                        .usernameParameter("loginId")
                        .passwordParameter("password")

                        .permitAll()
                );


        http
                .csrf((auth) -> auth.disable());

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){


        return new BCryptPasswordEncoder();
    }
}
