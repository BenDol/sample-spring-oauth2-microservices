--INSERT INTO user (username,email, password, activated) VALUES ('piomin', 'piotr.minkowski@gmail.com', 'piot123', true);
INSERT INTO users (username,email, password, activated) VALUES ('piomin', 'piotr.minkowski@gmail.com', '15eefd099f840a5d278544c8eb22d6beee6b1c4725fee0184128696615b353a2', true);
INSERT INTO users (username,email, password, activated) VALUES ('dolb90@gmail.com', 'dolb90@gmail.com', '15eefd099f840a5d278544c8eb22d6beee6b1c4725fee0184128696615b353a2', true);

INSERT INTO authority (name) VALUES ('ROLE_USER');
INSERT INTO authority (name) VALUES ('ROLE_ADMIN');

INSERT INTO user_authority (username,authority) VALUES ('piomin', 'ROLE_USER');
INSERT INTO user_authority (username,authority) VALUES ('piomin', 'ROLE_ADMIN');

INSERT INTO user_authority (username,authority) VALUES ('dolb90@gmail.com', 'ROLE_USER');
INSERT INTO user_authority (username,authority) VALUES ('dolb90@gmail.com', 'ROLE_ADMIN');

INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, access_token_validity, additional_information)
VALUES ('account-service', '$2a$10$s7rR9qxaUnOJaE3J6ZSICupQxm.xTJhvScmXV.ylsI3AIY5OMXp.q', 'read', 'authorization_code,password,refresh_token,implicit', '900', '{}');
INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, access_token_validity, additional_information)
VALUES ('customer-service', '$2a$10$s7rR9qxaUnOJaE3J6ZSICupQxm.xTJhvScmXV.ylsI3AIY5OMXp.q', 'read', 'authorization_code,password,refresh_token,implicit', '900', '{}');
INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, access_token_validity, additional_information)
VALUES ('budget-app', 'secret', 'read', 'authorization_code,password,refresh_token,implicit', '900', '{}');
