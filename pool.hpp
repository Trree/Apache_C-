#ifndef MOD_PASSAUTH_DETAIL_POOL_HPP_
#define MOD_PASSAUTH_DETAIL_POOL_HPP_

namespace mod_passauth {
namespace detail {

/* Helper function for pool_register_delete. */
template <typename T>
apr_status_t delete_function(void *object) {
  delete static_cast<T *>(object);
  return APR_SUCCESS;
}

/* Register a C++ object to be deleted with a pool. */
template <typename T>
void pool_register_delete(apr_pool_t* pool, T* object) {
  /*
   * Note that the "child cleanup" argument below doesn't apply to us, so we
   * use apr_pool_cleanup_null, which is a no-op cleanup function.
   */
  apr_pool_cleanup_register(pool, object,
                            delete_function<T>,  /* cleanup function */
                            apr_pool_cleanup_null);  /* child cleanup */
}

/*
 * Un-register a C++ object from deletion with a pool. Essentially, this
 * undoes a previous call to pool_register_delete with the same pool and object.
 */
template <typename T>
void pool_unregister_delete(apr_pool_t* pool, T* object) {
  apr_pool_cleanup_kill(pool, object, delete_function<T>);
}

} /* namesapce detail */
} /* namespace mod_passauth */

#endif /* MOD_PASSAUTH_DETAIL_POOL_HPP_ */
