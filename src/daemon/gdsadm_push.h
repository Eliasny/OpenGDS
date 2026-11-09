/* gdsadm commands over OPC UA (gdsadm_push.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSADM_PUSH_H
#define OPENGDS_GDSADM_PUSH_H

int gdsadm_apps_register(int argc, char **argv);
int gdsadm_push_now(int argc, char **argv);
int gdsadm_push_setup(int argc, char **argv);
int gdsadm_push_keycred(int argc, char **argv);
int gdsadm_push_keycred_delete(int argc, char **argv);
int gdsadm_apps_unregister(int argc, char **argv);
int gdsadm_certs_revoke(int argc, char **argv);
int gdsadm_apps_import(int argc, char **argv);
/* gdsadm roles list|add-identity|remove-identity|add-app|remove-app */
int gdsadm_roles(int argc, char **argv);

#endif
