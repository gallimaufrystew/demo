
#include "axis2_svc_skeleton.h"
#include "strop.h"
#include <axutil_array_list.h>
#include <stdio.h>

#if __cplusplus
extern "C" {
#endif

    int AXIS2_CALL strop_free(
        axis2_svc_skeleton_t *svc_skeleton,
        const axutil_env_t *env);

    /*
     * This method invokes the right service method
     */
    axiom_node_t *AXIS2_CALL strop_invoke(
        axis2_svc_skeleton_t *svc_skeleton,
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_msg_ctx_t *msg_ctx);

    int AXIS2_CALL strop_init(
        axis2_svc_skeleton_t *svc_skeleton,
        const axutil_env_t *env);

    static const axis2_svc_skeleton_ops_t strop_svc_skeleton_ops_var = {
        strop_init,
        strop_invoke,
        NULL,
        strop_free
    };

    AXIS2_EXTERN axis2_svc_skeleton_t *AXIS2_CALL
    axis2_strop_create(const axutil_env_t *env)
    {
        axis2_svc_skeleton_t *svc_skeleton = NULL;
        svc_skeleton = (axis2_svc_skeleton_t *)AXIS2_MALLOC(env->allocator, sizeof(axis2_svc_skeleton_t));

        svc_skeleton->ops = &strop_svc_skeleton_ops_var;

        svc_skeleton->func_array = NULL;

        return svc_skeleton;
    }

    int AXIS2_CALL
    strop_init(axis2_svc_skeleton_t *svc_skeleton,const axutil_env_t *env)
    {
        std::cout << "service init" << "\n";
        return AXIS2_SUCCESS;
    }

    int AXIS2_CALL
    strop_free(axis2_svc_skeleton_t *svc_skeleton,const axutil_env_t *env)
    {
        std::cout << "service exit" << "\n";
        if (svc_skeleton) {
            AXIS2_FREE(env->allocator, svc_skeleton);
            svc_skeleton = NULL;
        }
        return AXIS2_SUCCESS;
    }

    /*
     * This method invokes the right service method
     */
    axiom_node_t *AXIS2_CALL
    strop_invoke(
        axis2_svc_skeleton_t *svc_skeleton,
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_msg_ctx_t *msg_ctx)
    {
        if (!node) {
            std::cout << "invalid request" << "\n";
            /** Note: return a SOAP fault here */
            return node;
        }

        if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT) {
            std::cout << "node type is not AXIOM_ELEMENT" << "\n";
            return nullptr;
        }

        axiom_element_t *element = nullptr;
        element = (axiom_element_t *) axiom_node_get_data_element(node, env);
        if (!element) {
            std::cout << "! element" << "\n";
            return nullptr;
        }

        axis2_char_t *op_name = axiom_element_get_localname(element, env);
        if (!op_name) {
            return nullptr;
        }

        std::cout << "op name >> " << op_name << "\n";

        if (axutil_strcmp(op_name, "add") == 0) {
            return axis2_strop_add(env, node);
        }
        if (axutil_strcmp(op_name, "reverse") == 0) {
            return axis2_strop_reverse(env, node);
        }
    }

    /**
     * Following block distinguish the exposed part of the dll.
     */

    AXIS2_EXPORT int
    axis2_get_instance(
        struct axis2_svc_skeleton **inst,
        const axutil_env_t *env)
    {
        *inst = axis2_strop_create(env);
        if (!(*inst)) {
            return AXIS2_FAILURE;
        }
        return AXIS2_SUCCESS;
    }

    AXIS2_EXPORT int
    axis2_remove_instance(
        axis2_svc_skeleton_t *inst,
        const axutil_env_t *env)
    {
        axis2_status_t status = AXIS2_FAILURE;
        if (inst) {
            status = AXIS2_SVC_SKELETON_FREE(inst, env);
        }
        return status;
    }

#if __cplusplus
}
#endif
