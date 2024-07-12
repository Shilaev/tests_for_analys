package com.smk.ui4vs.services.testcontainers;


import com.smk.ui4vs.models.roles_model.*;
import com.smk.ui4vs.services.SecurityService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Execution;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;

import javax.security.auth.login.AccountLockedException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.junit.jupiter.api.parallel.ExecutionMode.CONCURRENT;

@SpringBootTest
@TestInstance(PER_CLASS)
public class SecurityServiceTests {

    //region    dependencies
    private final SecurityService securityService;

    @Autowired public SecurityServiceTests(SecurityService securityService) {
        this.securityService = securityService;
    }
    //endregion dependencies

    //region    setup testcontainer
    @Container
    private static final PostgreSQLContainer<?> postgresContainer = new PostgreSQLContainer<>("postgres:16")
            .withInitScript("create-schemas.sql");

    static {
        postgresContainer.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgresContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgresContainer::getUsername);
        registry.add("spring.datasource.password", postgresContainer::getPassword);
    }
    //endregion setup testcontainer

    //region    fields
    String namespaceTitle;
    String namespaceDescription;

    String groupTitle;

    String authorityTitle;
    String authorityDescription;

    String roleTitle;
    String roleDescription;

    String username;
    String password;
    String firstName;
    String lastName;
    //endregion fields


    @Test @Transactional @Execution(CONCURRENT)
    void when_createNamespace_withTitleAndDescription_then_allSuccess() {

        //region    Arrange
        namespaceTitle = "Супер_Админ";
        namespaceDescription = "Описание пространства имен Супер_Админ";

        groupTitle = "Админ_Группа";

        authorityTitle = "SUPER_ADMIN";
        authorityDescription = "includes every single action";

        roleTitle = "super-admin";
        roleDescription = "role that includes every single action";

        username = "admin";
        password = "admin";
        firstName = "Админ";
        lastName = "Админ";
        //endregion Arrange

        //region    Act
        Namespace namespace = securityService.createNamespace(namespaceTitle, namespaceDescription);
        Group group = securityService.createGroupWithDefaults(groupTitle, namespaceTitle);
        Authority authority = securityService.createAuthority(authorityTitle, authorityDescription);
        Role role = securityService.createRole(roleTitle, roleDescription, Set.of(authority.getTitle()));
        User user = securityService.createUserWithDefaults(username, password, firstName, lastName, namespaceTitle, Set.of(role.getTitle()));
        //endregion Act

        //region    Assert
        assertThat(securityService.findNamespaceByTitle(namespace.getTitle())).isNotNull().isInstanceOf(Namespace.class);
        assertThat(securityService.findGroupByTitle(group.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findAuthorityByTitle((authority.getTitle()))).isNotNull().isInstanceOf(Authority.class);
        assertThat(securityService.findRoleByTitle(role.getTitle())).isNotNull().isInstanceOf(Role.class);
        assertThat(securityService.findUserByUsername(user.getUsername())).isNotNull().isInstanceOf(User.class);
        //endregion Assert

    }

    @Test @Transactional @Execution(CONCURRENT)
    void when_replaceUser_then_ok() throws AccountLockedException {

        //region    Arrange
        namespaceTitle = "Супер_Админ";
        namespaceDescription = "Описание пространства имен Супер_Админ";

        String sourceGroupTitle = "Админ_Группа1";
        String targetGroupTitle = "Админ_Группа2";

        authorityTitle = "SUPER_ADMIN";
        authorityDescription = "includes every single action";

        roleTitle = "super-admin";
        roleDescription = "role that includes every single action";

        username = "admin";
        password = "admin";
        firstName = "Админ";
        lastName = "Админ";
        //endregion Arrange

        //region    Act
        Namespace namespace = securityService.createNamespace(namespaceTitle, namespaceDescription);
        Group sourceGroup = securityService.createGroupWithDefaults(sourceGroupTitle, namespaceTitle);
        Group targetGroup = securityService.createGroupWithDefaults(targetGroupTitle, namespaceTitle);
        Authority authority = securityService.createAuthority(authorityTitle, authorityDescription);
        Role role = securityService.createRole(roleTitle, roleDescription, Set.of(authority.getTitle()));
        User user = securityService.createUserWithDefaults(username, password, firstName, lastName, namespaceTitle, Set.of(role.getTitle()));

        securityService.addUserIntoGroup(sourceGroupTitle, username);
        //endregion Act

        //region    Assert
        assertThat(securityService.findNamespaceByTitle(namespace.getTitle())).isNotNull().isInstanceOf(Namespace.class);
        assertThat(securityService.findGroupByTitle(sourceGroup.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findGroupByTitle(targetGroup.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findAuthorityByTitle((authority.getTitle()))).isNotNull().isInstanceOf(Authority.class);
        assertThat(securityService.findRoleByTitle(role.getTitle())).isNotNull().isInstanceOf(Role.class);
        assertThat(securityService.findUserByUsername(user.getUsername())).isNotNull().isInstanceOf(User.class);
        //endregion Assert

        //region    Act
        securityService.replaceUserToGroup(username, sourceGroupTitle, targetGroupTitle);
        //endregion Act

        //region    Assert
        assertThat(securityService.getAllUsersFromGroup(sourceGroup.getTitle())).doesNotContain(user);
        assertThat(securityService.getAllUsersFromGroup(targetGroup.getTitle())).contains(user);
        assertThat(securityService.getAllGroupsFromUser(username)).contains(targetGroup);
        assertThat(securityService.getAllGroupsFromUser(username)).doesNotContain(sourceGroup);
        //endregion Assert
    }

    @Test @Transactional @Execution(CONCURRENT)
    void when_replaceUser_and_targetGroup_alreadyHasThis_user_then_exception() throws AccountLockedException {

        //region    Arrange
        namespaceTitle = "Супер_Админ";
        namespaceDescription = "Описание пространства имен Супер_Админ";

        String sourceGroupTitle = "Админ_Группа1";
        String targetGroupTitle = "Админ_Группа2";

        authorityTitle = "SUPER_ADMIN";
        authorityDescription = "includes every single action";

        roleTitle = "super-admin";
        roleDescription = "role that includes every single action";

        username = "admin";
        password = "admin";
        firstName = "Админ";
        lastName = "Админ";
        //endregion Arrange

        //region    Act
        Namespace namespace = securityService.createNamespace(namespaceTitle, namespaceDescription);
        Group sourceGroup = securityService.createGroupWithDefaults(sourceGroupTitle, namespaceTitle);
        Group targetGroup = securityService.createGroupWithDefaults(targetGroupTitle, namespaceTitle);
        Authority authority = securityService.createAuthority(authorityTitle, authorityDescription);
        Role role = securityService.createRole(roleTitle, roleDescription, Set.of(authority.getTitle()));
        User user = securityService.createUserWithDefaults(username, password, firstName, lastName, namespaceTitle, Set.of(role.getTitle()));

        securityService.addUserIntoGroup(sourceGroupTitle, username);
        securityService.addUserIntoGroup(targetGroupTitle, username);
        //endregion Act

        //region    Assert
        assertThat(securityService.findNamespaceByTitle(namespace.getTitle())).isNotNull().isInstanceOf(Namespace.class);
        assertThat(securityService.findGroupByTitle(sourceGroup.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findGroupByTitle(targetGroup.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findAuthorityByTitle((authority.getTitle()))).isNotNull().isInstanceOf(Authority.class);
        assertThat(securityService.findRoleByTitle(role.getTitle())).isNotNull().isInstanceOf(Role.class);
        assertThat(securityService.findUserByUsername(user.getUsername())).isNotNull().isInstanceOf(User.class);
        //endregion Assert

        //region    Assert
        assertThrows(RuntimeException.class, () -> securityService.replaceUserToGroup(username, sourceGroupTitle, targetGroupTitle), "user already exists in this group");
        //endregion Assert
    }

}
