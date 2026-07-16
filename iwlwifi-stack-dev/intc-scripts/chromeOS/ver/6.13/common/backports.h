static inline void
hrtimer_setup(struct hrtimer *timer,
              enum hrtimer_restart (*function)(struct hrtimer *),
              clockid_t clock_id, enum hrtimer_mode mode)
{
	hrtimer_init(timer, clock_id, mode);
	timer->function = function;
}
