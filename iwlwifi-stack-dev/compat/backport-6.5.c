// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/gso.h>

#if LINUX_VERSION_IS_GEQ(6,2,0) && IS_ENABLED(CONFIG_KUNIT)
#include <kunit/test.h>
#include <kunit/resource.h>

struct kunit_action_ctx {
	struct kunit_resource res;
	void (*func)(void *);
	void *ctx;
};

static void __kunit_action_free(struct kunit_resource *res)
{
	struct kunit_action_ctx *action_ctx = container_of(res, struct kunit_action_ctx, res);

	action_ctx->func(action_ctx->ctx);
}


int kunit_add_action(struct kunit *test, void (*action)(void *), void *ctx)
{
	struct kunit_action_ctx *action_ctx;

	KUNIT_ASSERT_NOT_NULL_MSG(test, action, "Tried to action a NULL function!");

	action_ctx = kzalloc(sizeof(*action_ctx), GFP_KERNEL);
	if (!action_ctx)
		return -ENOMEM;

	action_ctx->func = action;
	action_ctx->ctx = ctx;

	action_ctx->res.should_kfree = true;
	/* As init is NULL, this cannot fail. */
	__kunit_add_resource(test, NULL, __kunit_action_free, &action_ctx->res, action_ctx);

	return 0;
}
EXPORT_SYMBOL_GPL(kunit_add_action);

int kunit_add_action_or_reset(struct kunit *test, void (*action)(void *),
			      void *ctx)
{
	int res = kunit_add_action(test, action, ctx);

	if (res)
		action(ctx);
	return res;
}
EXPORT_SYMBOL_GPL(kunit_add_action_or_reset);

static bool __kunit_action_match(struct kunit *test,
				struct kunit_resource *res, void *match_data)
{
	struct kunit_action_ctx *match_ctx = (struct kunit_action_ctx *)match_data;
	struct kunit_action_ctx *res_ctx = container_of(res, struct kunit_action_ctx, res);

	/* Make sure this is a free function. */
	if (res->free != __kunit_action_free)
		return false;

	/* Both the function and context data should match. */
	return (match_ctx->func == res_ctx->func) && (match_ctx->ctx == res_ctx->ctx);
}

void kunit_remove_action(struct kunit *test,
			void (*action)(void *),
			void *ctx)
{
	struct kunit_action_ctx match_ctx;
	struct kunit_resource *res;

	match_ctx.func = action;
	match_ctx.ctx = ctx;

	res = kunit_find_resource(test, __kunit_action_match, &match_ctx);
	if (res) {
		/* Remove the free function so we don't run the action. */
		res->free = NULL;
		kunit_remove_resource(test, res);
		kunit_put_resource(res);
	}
}
EXPORT_SYMBOL_GPL(kunit_remove_action);

void kunit_release_action(struct kunit *test,
			 void (*action)(void *),
			 void *ctx)
{
	struct kunit_action_ctx match_ctx;
	struct kunit_resource *res;

	match_ctx.func = action;
	match_ctx.ctx = ctx;

	res = kunit_find_resource(test, __kunit_action_match, &match_ctx);
	if (res) {
		kunit_remove_resource(test, res);
		/* We have to put() this here, else free won't be called. */
		kunit_put_resource(res);
	}
}
EXPORT_SYMBOL_GPL(kunit_release_action);
#endif /* LINUX_VERSION_IS_GEQ(6,2,0) && IS_ENABLED(CONFIG_KUNIT) */
