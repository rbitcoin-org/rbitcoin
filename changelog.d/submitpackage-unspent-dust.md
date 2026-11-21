Fixed

- **`submitpackage` names Core's package reason in `package_msg`.** When
  the package evaluation refuses a 0-fee parent because its child leaves
  the ephemeral anchor unspent, `package_msg` is `unspent-dust`; when the
  package would exceed the cluster limit, it is `too-large-cluster`. Both
  were `transaction failed`. The per-member errors are unchanged. Checks
  run in a different order than Core's, so a package that fails several
  rules, or a script, may name a different reason.
