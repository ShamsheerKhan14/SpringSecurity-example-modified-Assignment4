package ca.sheridancollege.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class HomeController {

    @GetMapping("/")
    public String goHome() {
        return "index";
    }

    @GetMapping("/user")
    public String goToUserSecured() {
        return "secured/user/index";
    }

    @GetMapping("/manager")
    public String goToSecuredForManager() {
        return "secured/manager/manager_area";
    }

    @GetMapping("/secured")
    public String goToSecured() {
        return "secured/user/gateway";
    }

    @GetMapping("/login")
    public String goToCustomLogin() {
        return "login";
    }

    @GetMapping("/permission-denied")
    public String goToDenied() {
        return "error/permission-denied";
    }

    @PostMapping("/logout")
    public String goToCustomLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:/logoutSuccess";
    }

    @GetMapping("/error")
    public String goToError() {
        return "error/error";
    }
}