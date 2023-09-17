package com.spring.securityPractice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.securityPractice.SpringApplicationContext;
import com.spring.securityPractice.constants.AppConstants;
import com.spring.securityPractice.model.FailedDto;
import com.spring.securityPractice.model.ResponseDto;
import com.spring.securityPractice.model.UserDto;
import com.spring.securityPractice.model.UserLoginRequestModel;
import com.spring.securityPractice.service.UserService;
import com.spring.securityPractice.utils.JWTUtils;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.List;
import java.util.NoSuchElementException;

@AllArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			UserLoginRequestModel creds = new ObjectMapper().readValue(request.getInputStream(),
					UserLoginRequestModel.class);
			return authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getPassword()));
		} catch (IOException e) {
			// log.info("Exception occured at attemptAuthentication method:
			// {}",e.getLocalizedMessage());
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		UserService userService = (UserService) SpringApplicationContext.getBean("userServiceImpl");

		String userId = ((User) authResult.getPrincipal()).getUsername();
		UserDto userDto = userService.getUser(userId);

		String accessToken = JWTUtils.generateToken(userId,
				List.of(new String("ROLE_" + userDto.getRole())));

		ResponseDto responseDto = new ResponseDto(userDto.getUserId(), AppConstants.TOKEN_PREFIX + accessToken);
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(new ObjectMapper().writeValueAsString(responseDto));
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		FailedDto failedDto = new FailedDto();
		try {
			throw failed;
		} catch (BadCredentialsException e) {
			failedDto.setError("Authentication failed: Email or password is incorrect!");
		} catch (AccountExpiredException e) {
			failedDto.setError("Authentication failed: Account has expired");
		} catch (NoSuchElementException e) {
			failedDto.setError("Authentication failed: Please provide the required fields");
		} catch (Exception e) {
			failedDto.setError(e.getMessage());
		} 
		finally {
			response.setContentType("application/json");
			response.setCharacterEncoding("UTF-8");
			response.getWriter().write(new ObjectMapper().writeValueAsString(failedDto));
		}
	}

}
