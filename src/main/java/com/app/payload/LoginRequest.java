package com.app.payload;

import jakarta.validation.constraints.NotBlank;

public class LoginRequest {
	
	private Long id;//es un campo mientras(borrar)
	
	@NotBlank
	private String username;

	@NotBlank
	private String password;
	
	

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
