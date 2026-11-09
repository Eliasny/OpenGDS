/* OpenGDS - gdsctl push-targets: the Servers opengdsd's push engine
 * manages (store table push_targets; docs/push.md "Scheduled pushes").
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSCTL_PUSH_TARGETS_H
#define OPENGDS_GDSCTL_PUSH_TARGETS_H

/* argv[1] is "push-targets". Exit status: 0 done, 1 not found, 2 usage or
 * a store that cannot be used. */
int gdsctl_push_targets(int argc, char **argv);

#endif
