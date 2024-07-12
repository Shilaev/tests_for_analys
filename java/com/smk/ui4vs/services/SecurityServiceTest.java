package com.smk.ui4vs.services;

import com.smk.ui4vs.models.roles_model.Namespace;
import com.smk.ui4vs.models.roles_model.Role;
import com.smk.ui4vs.models.roles_model.User;
import com.smk.ui4vs.repositories.RolesRepository;
import com.smk.ui4vs.repositories.UsersRepository;
import com.smk.ui4vs.utils.SpecificationUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.parallel.ExecutionMode.CONCURRENT;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {

    @InjectMocks private SecurityService securityService;
    @Mock private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    @Mock private RolesRepository rolesRepository;
    @Mock private UsersRepository usersRepository;


    @Test @Execution(CONCURRENT)
    void when_findAllBySort_then_successFound() {
        // Arrange
        PageRequest pageable = PageRequest.of(0, 10, Sort.by("title"));
        Specification<Role> specification = SpecificationUtils.smkAdminFilter("title");

        Role role1 = mock(Role.class);
        Role role2 = mock(Role.class);
        Role role3 = mock(Role.class);

        when(rolesRepository.findAll(specification, pageable.getSort()))
                .thenReturn(List.of(role1, role2, role3));

        // Act
        Set<Role> list = securityService.findAllBySort(specification, Role.class, pageable);

        // Assert
        Assertions.assertEquals(3, list.size());
        verify(rolesRepository).findAll(specification, pageable.getSort());
    }

}