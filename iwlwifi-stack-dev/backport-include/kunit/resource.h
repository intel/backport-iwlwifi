#ifndef __BP_KUNIT_RESOURCE_H
#define __BP_KUNIT_RESOURCE_H
#include <linux/version.h>

#include_next <kunit/resource.h>

#if LINUX_VERSION_IS_LESS(6,6,0) && LINUX_VERSION_IS_GEQ(6,2,0)
/* A 'deferred action' function to be used with kunit_add_action. */
typedef void (kunit_action_t)(void *);

/**
 * kunit_add_action() - Call a function when the test ends.
 * @test: Test case to associate the action with.
 * @action: The function to run on test exit
 * @ctx: Data passed into @func
 *
 * Defer the execution of a function until the test exits, either normally or
 * due to a failure.  @ctx is passed as additional context. All functions
 * registered with kunit_add_action() will execute in the opposite order to that
 * they were registered in.
 *
 * This is useful for cleaning up allocated memory and resources, as these
 * functions are called even if the test aborts early due to, e.g., a failed
 * assertion.
 *
 * See also: devm_add_action() for the devres equivalent.
 *
 * Returns:
 *   0 on success, an error if the action could not be deferred.
 */
int kunit_add_action(struct kunit *test, kunit_action_t *action, void *ctx);

/**
 * kunit_add_action_or_reset() - Call a function when the test ends.
 * @test: Test case to associate the action with.
 * @action: The function to run on test exit
 * @ctx: Data passed into @func
 *
 * Defer the execution of a function until the test exits, either normally or
 * due to a failure.  @ctx is passed as additional context. All functions
 * registered with kunit_add_action() will execute in the opposite order to that
 * they were registered in.
 *
 * This is useful for cleaning up allocated memory and resources, as these
 * functions are called even if the test aborts early due to, e.g., a failed
 * assertion.
 *
 * If the action cannot be created (e.g., due to the system being out of memory),
 * then action(ctx) will be called immediately, and an error will be returned.
 *
 * See also: devm_add_action_or_reset() for the devres equivalent.
 *
 * Returns:
 *   0 on success, an error if the action could not be deferred.
 */
int kunit_add_action_or_reset(struct kunit *test, kunit_action_t *action,
			      void *ctx);

/**
 * kunit_remove_action() - Cancel a matching deferred action.
 * @test: Test case the action is associated with.
 * @action: The deferred function to cancel.
 * @ctx: The context passed to the deferred function to trigger.
 *
 * Prevent an action deferred via kunit_add_action() from executing when the
 * test terminates.
 *
 * If the function/context pair was deferred multiple times, only the most
 * recent one will be cancelled.
 *
 * See also: devm_remove_action() for the devres equivalent.
 */
void kunit_remove_action(struct kunit *test,
			 kunit_action_t *action,
			 void *ctx);

/**
 * kunit_release_action() - Run a matching action call immediately.
 * @test: Test case the action is associated with.
 * @action: The deferred function to trigger.
 * @ctx: The context passed to the deferred function to trigger.
 *
 * Execute a function deferred via kunit_add_action()) immediately, rather than
 * when the test ends.
 *
 * If the function/context pair was deferred multiple times, it will only be
 * executed once here. The most recent deferral will no longer execute when
 * the test ends.
 *
 * kunit_release_action(test, func, ctx);
 * is equivalent to
 * func(ctx);
 * kunit_remove_action(test, func, ctx);
 *
 * See also: devm_release_action() for the devres equivalent.
 */
void kunit_release_action(struct kunit *test,
			  kunit_action_t *action,
			  void *ctx);
#endif /* LINUX_VERSION_IS_LESS(6,6,0) && LINUX_VERSION_IS_GEQ(6,2,0) */

#endif /* __BP_KUNIT_RESOURCE_H */
