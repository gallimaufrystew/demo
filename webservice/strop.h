
#ifndef STROP_INCLUDED__H
#define STROP_INCLUDED__H

#include <axis2_svc_skeleton.h>
#include <axutil_log_default.h>
#include <axutil_error_default.h>
#include <axiom_text.h>
#include <axiom_node.h>
#include <axiom_element.h>
#include <iostream>

axiom_node_t *axis2_strop_add(
    const axutil_env_t *env,
    axiom_node_t *node);
axiom_node_t *axis2_strop_reverse(
    const axutil_env_t *env,
    axiom_node_t *node);

#endif /* STROP_INCLUDED__H */
