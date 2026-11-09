/* gdsadm watch: live audit events and alarms of a GDS (gdsadm_watch.c;
 * OpenGDS plan W5, tools "cmd_watch.c").
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSADM_WATCH_H
#define OPENGDS_GDSADM_WATCH_H

#include <open62541/types.h>

#include <stdbool.h>
#include <stdio.h>

/* The select clauses, in this order (OPC 10000-4 §7.7.4 SimpleAttributeOperand). */
typedef enum {
    GW_EVENT_ID,      /* BaseEventType (OPC 10000-5 §6.4.2) */
    GW_EVENT_TYPE,
    GW_SOURCE_NODE,
    GW_SOURCE_NAME,
    GW_TIME,
    GW_MESSAGE,
    GW_SEVERITY,
    GW_CONDITION_ID,  /* ConditionType, empty path, NodeId attribute (OPC 10000-9 §5.5.2) */
    GW_CONDITION_NAME,
    GW_RETAIN,
    GW_ENABLED,       /* ConditionType EnabledState/Id */
    GW_ACKED,         /* AcknowledgeableConditionType AckedState/Id (OPC 10000-9 §5.7.2) */
    GW_ACTIVE,        /* AlarmConditionType ActiveState/Id (OPC 10000-9 §5.8.2) */
    GW_CLIENT_USER,   /* AuditEventType ClientUserId (OPC 10000-5 §6.4.3) */
    GW_STATUS,        /* AuditEventType Status */
    GW_NFIELDS
} gw_field;

/* One event as one line: text, or one JSON object (JSON Lines). fields
 * holds GW_NFIELDS values in gw_field order; an empty Variant is a field
 * the event does not have and is left out. typeName is the BrowseName of
 * the EventType, or NULL. refresh: the event came in a ConditionRefresh
 * (OPC 10000-9 §5.5.7), so it is a Condition's current state, not news. */
void gdsadm_watch_print(FILE *out, bool json, const UA_Variant *fields, const char *typeName,
                        bool refresh);

/* gdsadm watch --url URL --user NAME --password-file F --trust CA.der
 *              [--trust DER]... [--crl DER]... [--json] [--count N] [--seconds N] */
int gdsadm_watch(int argc, char **argv);

#endif
