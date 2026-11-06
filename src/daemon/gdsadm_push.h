/* gdsadm commands over OPC UA (gdsadm_push.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSADM_PUSH_H
#define OPENGDS_GDSADM_PUSH_H

int gdsadm_apps_register(int argc, char **argv);
int gdsadm_push_now(int argc, char **argv);

#endif
