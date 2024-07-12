package com.smk.ui4vs.services.testcontainers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.smk.ui4vs.models.dto.UserDTO;
import com.smk.ui4vs.models.roles_model.*;
import com.smk.ui4vs.services.SecurityService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;

import java.util.Set;

import static com.smk.ui4vs.models.constants.Global.SAVE;
import static com.smk.ui4vs.models.constants.Global.USERS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(PER_CLASS)
public class UsersControllerTests {

    //region    dependencies
    private final SecurityService securityService;
    private final MockMvc mvc;
    private final ObjectMapper objectMapper;

    @Autowired
    public UsersControllerTests(SecurityService securityService, MockMvc mvc, ObjectMapper objectMapper) {
        this.securityService = securityService;
        this.mvc = mvc;
        this.objectMapper = objectMapper;
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


    @Test
    void name() throws Exception {
        //region    Arrange
        namespaceTitle = "Супер_Админ";
        namespaceDescription = "Описание пространства имен Супер_Админ";

        groupTitle = "Админ_Группа1";

        authorityTitle = "ADMIN";
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

        securityService.addUserIntoGroup(groupTitle, username);
        //endregion Act

        //region    Assert
        assertThat(securityService.findNamespaceByTitle(namespace.getTitle())).isNotNull().isInstanceOf(Namespace.class);
        assertThat(securityService.findGroupByTitle(group.getTitle())).isNotNull().isInstanceOf(Group.class);
        assertThat(securityService.findAuthorityByTitle((authority.getTitle()))).isNotNull().isInstanceOf(Authority.class);
        assertThat(securityService.findRoleByTitle(role.getTitle())).isNotNull().isInstanceOf(Role.class);
        assertThat(securityService.findUserByUsername(user.getUsername())).isNotNull().isInstanceOf(User.class);
        //endregion Assert

        UserDTO userDTO = new UserDTO(null, "тестимя", "тестфамилия", null, "testusername", Set.of(roleTitle), groupTitle, null, null, null);

        String userDtoJson = objectMapper.writeValueAsString(userDTO);

        mvc.perform(post(USERS + "/" + SAVE)
                .with(user(user)).with(csrf())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(userDtoJson))
                .andExpect(status().isOk());
    }

}
