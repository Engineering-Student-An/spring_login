package practice.login.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import practice.login.domain.User;
import practice.login.domain.UserRole;
import practice.login.domain.dto.JoinRequest;
import practice.login.domain.dto.LoginRequest;
import practice.login.service.UserService;

@Controller
@RequiredArgsConstructor
@RequestMapping("/cookie-login")
public class CookieLoginController {

    private final UserService userService;

    @GetMapping(value = {"", "/"})
    public String home(@CookieValue(name = "userId", required = false)
                           Long userId, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        User loginUser = userService.getLoginUserById(userId);

        if (loginUser != null) {
            model.addAttribute("nickname", loginUser.getNickname());
        }

        return "home";
    }

    @GetMapping("/join")
    public String joinPage(Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }

    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest,
                       BindingResult bindingResult, Model model) {

        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        if(userService.checkLoginIdDuplicate(joinRequest.getLoginId())){
            bindingResult.addError(new FieldError
                    ("joinRequest",
                    "loginId",
                    "로그인 아이디가 중복됩니다."));

        }

        if (userService.checkNicknameDuplicate(joinRequest.getNickname())) {
            bindingResult.addError(new FieldError(
                    "joinRequest",
                    "nickname",
                    "닉네임이 중복됩니다."));
        }

        if(!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())){
            bindingResult.addError(new FieldError(
                    "joinRequest",
                    "passwordCheck",
                    "비밀번호가 일치하지 않습니다"));
        }

        if (bindingResult.hasErrors()) {
            return "join";
        }

        userService.join(joinRequest);
        return "redirect:/cookie-login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest, BindingResult bindingResult,
                        HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        User user = userService.login(loginRequest);

        // 로그인 아이디나 비밀번호가 틀린 경우 global error return
        if(user == null) {
            bindingResult.reject("loginFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if(bindingResult.hasErrors()) {
            return "login";
        }

        // 로그인 성공 => 쿠키 생성
        Cookie cookie = new Cookie("userId", String.valueOf(user.getId()));
        cookie.setMaxAge(60 * 60);  // 쿠키 유효 시간 : 1시간
        response.addCookie(cookie);

        return "redirect:/cookie-login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        Cookie cookie = new Cookie("userId", null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/cookie-login";
    }

    @GetMapping("/info")
    public String userInfo(@CookieValue(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        User loginUser = userService.getLoginUserById(userId);

        if(loginUser == null) {
            return "redirect:/cookie-login/login";
        }

        model.addAttribute("user", loginUser);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(@CookieValue(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        User loginUser = userService.getLoginUserById(userId);

        if(loginUser == null) {
            return "redirect:/cookie-login/login";
        }

        if(!loginUser.getRole().equals(UserRole.ADMIN)) {
            return "redirect:/cookie-login";
        }

        return "admin";
    }
}

