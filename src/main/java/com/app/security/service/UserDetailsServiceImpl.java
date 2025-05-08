package com.app.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.models.User;
import com.app.repository.UserRepository;

/*
 * – La interfaz UserDetailsService tiene un método para cargar el usuario por nombre de usuario y
 * devuelve un objeto UserDetails que Spring Security puede usar para autenticación y validación.
 * */
@Service
public class UserDetailsServiceImpl implements UserDetailsService{
	
	  @Autowired
	  UserRepository userRepository;

	  @Override
	  @Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		 User user = userRepository.findByUsername(username)
			        .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con username: " + username));

			    return UserDetailsImpl.build(user);
	}

}
