Changed

- **Crash safety rests on 512-byte atomic sectors.** The store now assumes the
  device writes a 512-byte sector whole and that nothing below the filesystem
  re-encodes larger units (for example dm-crypt with a 4 KiB sector on a
  512-byte disk, or a RAID 5/6 stripe without a write journal). An append, or
  a write inside one sector, needs no page mark. `txstat` stamps no longer
  arm `store/guard/txstat`: each cell is synced in place.
