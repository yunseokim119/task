package com.yunseo.task.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorController {
    @RequestMapping("/403")
    public String handleAccessDenied() {
        return "error/403";  // 403 오류 처리 페이지
    }
}