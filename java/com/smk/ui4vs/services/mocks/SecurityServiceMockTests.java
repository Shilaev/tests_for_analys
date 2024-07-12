package com.smk.ui4vs.services.mocks;


import com.smk.ui4vs.models.roles_model.*;
import com.smk.ui4vs.repositories.*;
import com.smk.ui4vs.services.DeactivatedTokensService;
import com.smk.ui4vs.services.SecurityService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.junit.jupiter.api.parallel.ExecutionMode.SAME_THREAD;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@TestInstance(PER_CLASS)
@ExtendWith(MockitoExtension.class)
public class SecurityServiceMockTests {

    //region    dependencies
    @Mock private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    @Mock private UsersRepository usersRepository;
    @Mock private AuthoritiesRepository authoritiesRepository;
    @Mock private RolesRepository rolesRepository;
    @Mock private TokensRepository tokensRepository;
    @Mock private DeactivatedTokensService deactivatedTokensService;

    @Mock private NamespaceRepository namespaceRepository;
    @Mock private GroupsRepository groupsRepository;

    @InjectMocks SecurityService securityService;
    //endregion dependencies


    @Test @Execution(SAME_THREAD)
    void when_createNamespace_withTitleAndDescription_then_allSuccess() {

        //region    Arrange
        String namespaceTitle = "Супер_Админ";
        String namespaceDescription = "Описание пространства имен Супер_Админ";
        UUID namespaceKey = UUID.randomUUID();
        Namespace namespace = new Namespace(namespaceTitle, namespaceKey, namespaceDescription, null, null, null);
        when(namespaceRepository.save(any(Namespace.class))).thenReturn(namespace);
        when(namespaceRepository.findByTitle(anyString())).thenReturn(Optional.of(namespace));


        String groupTitle = "Админ_Группа";
        UUID groupKey = UUID.randomUUID();
        Group group = new Group(groupKey, groupTitle, null, null, namespace);
        when(groupsRepository.save(any(Group.class))).thenReturn(group);
        when(groupsRepository.findByTitle(anyString())).thenReturn(Optional.of(group));


        String authorityTitle = "SUPER_ADMIN";
        String authorityDescription = "includes every single action";
        Authority authority = new Authority(authorityTitle, authorityDescription);
        when(authoritiesRepository.save(any(Authority.class))).thenReturn(authority);
        when(authoritiesRepository.findByTitle(anyString())).thenReturn(Optional.of(authority));


        String roleTitle = "super-admin";
        String roleDescription = "role that includes every single action";
        Role role = new Role(roleTitle, roleDescription, Set.of(authority));
        when(rolesRepository.save(any(Role.class))).thenReturn(role);
        when(rolesRepository.findByTitle(anyString())).thenReturn(Optional.of(role));


        String username = "admin";
        String password = "admin";
        String firstName = "Админ";
        String lastName = "Админ";
        User user = new User(username, password, firstName, lastName, namespace, Set.of(role));
        when(usersRepository.save(any(User.class))).thenReturn(user);
        when(usersRepository.findByUsername(anyString())).thenReturn(Optional.of(user));
        //endregion Arrange

        //region    Act
        Namespace namespaceForCheck = securityService.createNamespace(namespaceTitle, namespaceDescription);
        Group groupForCheck = securityService.createGroupWithDefaults(groupTitle, namespaceTitle);
        Authority authorityForCheck = securityService.createAuthority(authorityTitle, authorityDescription);
        Role roleForCheck = securityService.createRole(roleTitle, roleDescription, Set.of(authorityForCheck.getTitle()));
        User userForCheck = securityService.createUserWithDefaults(username, password, firstName, lastName, namespaceTitle, Set.of(roleForCheck.getTitle()));
        //endregion Act

        //region    Assert
        assertThat(securityService.findNamespaceByTitle(namespaceForCheck.getTitle())).isNotNull().isInstanceOf(Namespace.class);
        assertThat(securityService.findGroupByTitle(groupForCheck.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findAuthorityByTitle((authorityForCheck.getTitle()))).isNotNull().isInstanceOf(Authority.class);
        assertThat(securityService.findRoleByTitle(roleForCheck.getTitle())).isNotNull().isInstanceOf(Role.class);
        assertThat(securityService.findUserByUsername(userForCheck.getUsername())).isNotNull().isInstanceOf(User.class);
        //endregion Assert

    }
}
