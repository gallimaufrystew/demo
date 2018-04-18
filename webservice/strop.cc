
#include "strop.h"
#include <cstdint>
#include <stdio.h>
#include <algorithm>
#include <sstream>

axiom_node_t *
axis2_strop_reverse(
    const axutil_env_t *env,
    axiom_node_t *node)
{
    axiom_node_t *param1_node = nullptr;
    axiom_node_t *param1_text_node = nullptr;
    axis2_char_t *param1_str = nullptr;

    if (!node) {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL,
                        AXIS2_FAILURE);
        printf("client request ERROR: input parameter nullptr\n");
        return nullptr;
    }

    /* iterating to the first child element skipping (empty) text elements */
    for (param1_node = axiom_node_get_first_child(node, env);
            param1_node && axiom_node_get_node_type(param1_node, env) != AXIOM_ELEMENT;
            param1_node = axiom_node_get_next_sibling(param1_node, env));

    if (!param1_node) {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("service  ERROR: invalid XML in request\n");
        return nullptr;
    }
    param1_text_node = axiom_node_get_first_child(param1_node, env);
    if (!param1_text_node) {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("service  ERROR: invalid XML in request\n");
        return nullptr;
    }
    if (axiom_node_get_node_type(param1_text_node, env) == AXIOM_TEXT) {
        axiom_text_t *text =
            (axiom_text_t *) axiom_node_get_data_element(param1_text_node, env);
        if (text && axiom_text_get_value(text, env)) {
            param1_str = (axis2_char_t *) axiom_text_get_value(text, env);
        }
    } else {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("service ERROR: invalid XML in request\n");
        return nullptr;
    }

    if (param1_str) {

        axiom_element_t *ele1 = nullptr;
        axiom_node_t *node1 = nullptr, *node2 = nullptr;
        axiom_namespace_t *ns1 = nullptr;
        axiom_text_t *text1 = nullptr;

        std::cout << "reverse parameter >>> " << param1_str << "\n";

        int l = 0, r = axutil_strlen(param1_str) - 1;
        while (l <= r) {
            if (l != r) {
                std::swap(param1_str[l], param1_str[r]);
            }
            ++l;--r;
        }

        std::cout << "reverse out > " << param1_str << "\n";

        ns1 = axiom_namespace_create(env,"http://axis2/test/namespace1", "ns1");
        ele1 = axiom_element_create(env, nullptr, "result", ns1, &node1);
        text1 = axiom_text_create(env, node1, param1_str, &node2);

        return node1;
    }

    AXIS2_ERROR_SET(env->error,
                    AXIS2_ERROR_SVC_SKEL_INVALID_OPERATION_PARAMETERS_IN_SOAP_REQUEST,
                    AXIS2_FAILURE);
    printf("service ERROR: invalid parameters\n");
    return nullptr;
}

axiom_node_t *
axis2_strop_add(
    const axutil_env_t *env,
    axiom_node_t *node)
{
    axiom_node_t *param1_node = nullptr;
    axiom_node_t *param1_text_node = nullptr;
    axis2_char_t *param1_str = nullptr;

    if (!node) {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL,
                        AXIS2_FAILURE);
        printf("client request ERROR: input parameter nullptr\n");
        return nullptr;
    }

    /* iterating to the first child element skipping (empty) text elements */
    for (param1_node = axiom_node_get_first_child(node, env);
            param1_node && axiom_node_get_node_type(param1_node, env) != AXIOM_ELEMENT;
            param1_node = axiom_node_get_next_sibling(param1_node, env));

    if (!param1_node) {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("service  ERROR: invalid XML in request\n");
        return nullptr;
    }
    param1_text_node = axiom_node_get_first_child(param1_node, env);
    if (!param1_text_node) {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("service  ERROR: invalid XML in request\n");
        return nullptr;
    }
    if (axiom_node_get_node_type(param1_text_node, env) == AXIOM_TEXT) {
        axiom_text_t *text =
            (axiom_text_t *) axiom_node_get_data_element(param1_text_node, env);
        if (text && axiom_text_get_value(text, env)) {
            param1_str = (axis2_char_t *) axiom_text_get_value(text, env);
        }
    } else {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("service ERROR: invalid XML in request\n");
        return nullptr;
    }

    if (param1_str) {

        axis2_char_t res[2048] = {};

        std::cout << "add parameter >>> " << param1_str << "\n";

        axiom_element_t *ele1 = nullptr;
        axiom_node_t *node1 = nullptr, *node2 = nullptr;
        axiom_namespace_t *ns1 = nullptr;
        axiom_text_t *text1 = nullptr;

        std::istringstream iss(param1_str);

        long double sum = 0;
        long double val;

        while (iss >> val) {
            sum += val;
        }

        sprintf(res,"%Lg",sum);

        ns1 = axiom_namespace_create(env,"http://axis2/test/namespace1", "ns1");
        ele1 = axiom_element_create(env, nullptr, "result", ns1, &node1);
        text1 = axiom_text_create(env, node1, res, &node2);

        return node1;
    }

    AXIS2_ERROR_SET(env->error,
                    AXIS2_ERROR_SVC_SKEL_INVALID_OPERATION_PARAMETERS_IN_SOAP_REQUEST,
                    AXIS2_FAILURE);
    printf("service ERROR: invalid parameters\n");
    return nullptr;
}
