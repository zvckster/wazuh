/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agent-manager-blocks.h"

/* The <manager> children of one <agent> block that come after `position`. */
static int w_count_managers_in_agent(const OS_XML *xml, const xml_node *agent_block, unsigned int position)
{
    xml_node **children = OS_GetElementsbyNode(xml, agent_block);
    int count = 0;

    for (int i = 0; children && children[i]; i++) {
        if (children[i]->element && strcmp(children[i]->element, "manager") == 0 &&
            children[i]->key > position) {
            count++;
        }
    }

    OS_ClearNode(children);
    return count;
}

/* The <manager> blocks after `position` in the <agent> blocks of one root. */
static int w_count_managers_in_root(const OS_XML *xml, const xml_node *root, unsigned int position)
{
    xml_node **blocks = OS_GetElementsbyNode(xml, root);
    int count = 0;

    for (int i = 0; blocks && blocks[i]; i++) {
        if (blocks[i]->element && strcmp(blocks[i]->element, "agent") == 0) {
            count += w_count_managers_in_agent(xml, blocks[i], position);
        }
    }

    OS_ClearNode(blocks);
    return count;
}

int w_count_agent_manager_blocks_after(const OS_XML *xml, unsigned int position)
{
    xml_node **roots = OS_GetElementsbyNode(xml, NULL);
    int count = 0;

    for (int i = 0; roots && roots[i]; i++) {
        if (roots[i]->element && strcmp(roots[i]->element, WAZUHCONFIG) == 0) {
            count += w_count_managers_in_root(xml, roots[i], position);
        }
    }

    OS_ClearNode(roots);
    return count;
}
