package org.wstt.riskengineserver.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * 全局注入请求路径到模型, 替代Thymeleaf 3.1已废弃的#request对象
 */
@ControllerAdvice
public class WebConfig {

    @ModelAttribute("currentPath")
    public String currentPath(HttpServletRequest request) {
        return request.getRequestURI();
    }
}
