//package practice.login.controller;
//
//import jakarta.validation.Valid;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.ui.Model;
//import org.springframework.validation.BindingResult;
//import org.springframework.web.bind.annotation.*;
//import practice.login.domain.Member;
//import practice.login.domain.dto.JoinRequest;
//import practice.login.domain.dto.LoginRequest;
//import practice.login.jwt.JWTUtil;
//import practice.login.service.MemberService;
//
//import java.util.Collection;
//import java.util.Iterator;
//
//@RestController
//@RequiredArgsConstructor
//@RequestMapping("/jwt-login")
//public class JwtLoginController {
//
//    private final MemberService memberService;
//    private final JWTUtil jwtUtil;
//
//    @GetMapping(value = {"", "/"})
//    public String home(Model model) {
//
//        model.addAttribute("loginType", "jwt-login");
//        model.addAttribute("pageName", "스프링 시큐리티 JWT 로그인");
//
//        String loginId = SecurityContextHolder.getContext().getAuthentication().getName();
//
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
//        GrantedAuthority auth = iter.next();
//        String role = auth.getAuthority();
//
//        Member loginMember = memberService.getLoginMemberByLoginId(loginId);
//
//        if (loginMember != null) {
//            model.addAttribute("name", loginMember.getName());
//        }
//
//        return "home";
//    }
//
//    @GetMapping("/join")
//    public String joinPage(Model model) {
//
//        model.addAttribute("loginType", "jwt-login");
//        model.addAttribute("pageName", "스프링 시큐리티 JWT 로그인");
//
//        // 회원가입을 위해서 model 통해서 joinRequest 전달
//        model.addAttribute("joinRequest", new JoinRequest());
//        return "join";
//    }
//
//    @PostMapping("/join")
//    public String join(@Valid @ModelAttribute JoinRequest joinRequest,
//                       BindingResult bindingResult, Model model) {
//
//        model.addAttribute("loginType", "jwt-login");
//        model.addAttribute("pageName", "스프링 시큐리티 JWT 로그인");
//
//        // ID 중복 여부 확인
//        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
//            return "ID가 존재합니다.";
//        }
//
//
//        // 비밀번호 = 비밀번호 체크 여부 확인
//        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
//            return "비밀번호가 일치하지 않습니다.";
//        }
//
//        // 에러가 존재하지 않을 시 joinRequest 통해서 회원가입 완료
//        memberService.securityJoin(joinRequest);
//
//        // 회원가입 시 홈 화면으로 이동
//        return "redirect:/jwt-login";
//    }
//
//    @PostMapping("/login")
//    public String login(@RequestBody LoginRequest loginRequest){
//
//        Member member = memberService.login(loginRequest);
//
//
//        if(member==null){
//            return "ID 또는 비밀번호가 일치하지 않습니다!";
//        }
//
//        String token = jwtUtil.createJwt(member.getLoginId(), member.getRole(), 1000 * 60 * 60L);
//        return token;
//    }
//
//    @GetMapping("/info")
//    public String memberInfo(Authentication auth, Model model) {
//
//        Member loginMember = memberService.getLoginMemberByLoginId(auth.getName());
//
//        return "ID : " + loginMember.getLoginId() + "\n이름 : " + loginMember.getName() + "\nrole : " + loginMember.getRole();
//    }
//
//    @GetMapping("/admin")
//    public String adminPage(Model model) {
//
//        return "인가 성공!";
//    }
//}
