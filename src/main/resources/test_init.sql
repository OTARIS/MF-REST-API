insert into users(username, password, enabled) values ('testUser', '$2a$10$3P1Eg4fRVELG/Zn7JIYxs.ryDu.bSsZ1EhdcgMSVm1Jw0fRjtOzu2', 't');
insert into user_to_whitelist(username, whitelist) values ('testUser', 'DEFAULT_READ_WHITELIST');
insert into user_to_whitelist(username, whitelist) values ('testUser', 'DEFAULT_WRITE_WHITELIST');
insert into authorities(username, authority) values ('testUser', 'ROLE_MEMBER');
insert into authorities(username, authority) values ('testUser', 'ROLE_USER');
insert into whitelist(name) values ('TEST_WHITELIST');
