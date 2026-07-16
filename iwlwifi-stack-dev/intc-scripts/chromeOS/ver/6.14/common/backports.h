static inline ktime_t us_to_ktime(u64 us)
{
    return us * NSEC_PER_USEC;
}
