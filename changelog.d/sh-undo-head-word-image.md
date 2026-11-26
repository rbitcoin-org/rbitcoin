Fixed

- **A crash while a scripthash disconnect rolls back no longer loses
  neighboring index entries.** Putting back the old head word of an
  unlinked key rewrote one 8-byte word in place with no page image, so a
  torn write could erase the other keys on that 4 KiB head page. That
  write now goes behind a synced `*.ahead` image of the page, and open
  restores it (#2132).
