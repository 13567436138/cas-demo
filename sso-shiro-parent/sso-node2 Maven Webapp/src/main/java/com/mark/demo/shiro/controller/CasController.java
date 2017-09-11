package com.mark.demo.shiro.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/*
*hxp(hxpwangyi@126.com)
*2017年9月11日
*
*/
@Controller
@RequestMapping("")
public class CasController {
	
	@RequestMapping("/shiro-cas")
	public String shiroCas(){
		return "admins/main.ftl";
	}

}
