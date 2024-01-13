//package practice.login.jwt;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.filter.OncePerRequestFilter;
//import practice.login.domain.Member;
//import practice.login.domain.MemberRole;
//import practice.login.domain.dto.CustomUserDetails;
//
//import java.io.IOException;
//
//@RequiredArgsConstructor
//public class JWTFilter extends OncePerRequestFilter {
//
//    private final JWTUtil jwtUtil;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        // request에서 Authorization 헤더 찾음
//        String authorization = request.getHeader("Authorization");
//
//        // Authorization 헤더 검증
//        if(authorization == null || !authorization.startsWith("Bearer ")){
//
//            System.out.println("token null");
//            // 토큰이 유효하지 않으므로 request와 response를 다음 필터로 넘겨줌
//            filterChain.doFilter(request, response);
//
//            // 메서드 종료
//            return;
//        }
//
//        // Authorization에서 Bearer 접두사 제거
//        String token = authorization.split(" ")[1];
//
//        // token 소멸 시간 검증
//        if(jwtUtil.isExpired(token)){
//            System.out.println("token expired");
//            filterChain.doFilter(request, response);
//
//            // 메서드 종료
//            return;
//        }
//
//        // 최종적으로 token 검증 완료 => 일시적인 session 생성
//        // session에 user 정보 설정
//        String loginId = jwtUtil.getLoginId(token);
//        MemberRole role = MemberRole.valueOf(jwtUtil.getRole(token));
//
//        Member member = new Member();
//        member.setLoginId(loginId);
//        // 매번 요청마다 DB 조회해서 password 초기화 할 필요 x => 정확한 비밀번호 넣을 필요 없음 => 임시 비밀번호 설정!
//        member.setPassword("임시 비밀번호");
//        member.setRole(role);
//
//        // UserDetails에 회원 정보 객체 담기
//        CustomUserDetails customUserDetails = new CustomUserDetails(member);
//
//        // 스프링 시큐리티 인증 토큰 생성
//        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//
//        // 세션에 사용자 등록 => 일시적으로 user 세션 생성
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        // 다음 필터로 request, response 넘겨줌
//        filterChain.doFilter(request, response);
//    }
//}
