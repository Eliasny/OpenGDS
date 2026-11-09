-- OpenGDS store schema 6: Part 18 role mapping rules and managed users.
-- SPDX-License-Identifier: MPL-2.0
-- OPC 10000-18 §4.4: each Role has identity mapping rules (Identities),
-- an Applications list and an Endpoints list, changed with AddIdentity,
-- RemoveIdentity, AddApplication, RemoveApplication, AddEndpoint and
-- RemoveEndpoint. One row per rule; role is the Role's name as in the
-- users file (SecurityAdmin, DiscoveryAdmin, ...), so rows do not depend
-- on namespace indexes. kind: 1 identity, 2 application, 3 endpoint.
-- ctype is the IdentityCriteriaType (identity rules), mode the
-- MessageSecurityMode (endpoint rules, 0 = any); the text columns are ''
-- when unused. Rules added in the users file are not stored here.
CREATE TABLE role_rules (
    role      TEXT NOT NULL,
    kind      INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 3),
    ctype     INTEGER NOT NULL,
    criteria  TEXT NOT NULL,
    mode      INTEGER NOT NULL,
    policy    TEXT NOT NULL,
    transport TEXT NOT NULL,
    UNIQUE (role, kind, ctype, criteria, mode, policy, transport)
);
-- OPC 10000-18 §5: users managed with AddUser, ModifyUser, RemoveUser and
-- ChangePassword. credential is the users-file form
-- (pbkdf2-sha256:<iterations>:<salt hex>:<hash hex>), never a password;
-- config is the UserConfigurationMask.
CREATE TABLE users (
    name        TEXT PRIMARY KEY,
    credential  TEXT NOT NULL,
    config      INTEGER NOT NULL,
    description TEXT NOT NULL
);
