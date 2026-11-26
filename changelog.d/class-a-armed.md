Changed

- **Store meta 31 is the Class A arm.** A plain open of a schema 30
  datadir leaves it at 30. The first arm syncs meta 31 and then publishes
  `tear_guard/armed`, which names the slot generation open restores even
  when the live page is not all zeros. A newer slot written by a barrier
  that has not finished is ignored. With no `armed` file, a zero page
  still restores and a nonzero page is left as it was. `spent.body` is
  not part of that restore. An older binary refuses 31 `meta`.
