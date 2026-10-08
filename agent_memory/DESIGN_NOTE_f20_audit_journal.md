# Design note: append-only audit journal (F-20)

Status: implemented and tested in session 24 (EXECUTED). No wire/protocol change.

Problem: every append rewrote the whole audit log (O(n) bytes and an fsync of all of it).

Design: snapshot `P` (unchanged format, atomic temp+fsync+rename) plus `P.journal`:
frames `len | header-check | JSON record | payload-check`. Records: `Append{entry}` and
`Sig{seq,node_id,sig}` (co-signatures are merged into existing entries later, so they
must be journaled too). One `write_all` of whole frames, then `fsync`. A failed write is
rolled back with `set_len`. Past 4 MiB the node writes a new snapshot atomically and
removes the journal; a crash in between is harmless because replay is idempotent.

Torn-tail policy (the only tolerated defect): a frame cut short at EOF (header incomplete,
or valid header whose body runs past EOF) was never fsynced, so never acknowledged. It is
truncated at startup. Everything else is FATAL, as before (F-01): bad header check, bad
payload check, unparseable record, record contradicting the chain, signature for a missing
entry, broken hash chain. The header check keeps a flipped bit in the LAST frame's length
from being mistaken for a torn tail (that would silently drop an acknowledged entry).

Known limits: a power cut that leaves a full-length last frame with garbage content is
reported as corruption (fail-safe; needs an operator). The journal is a second file that
external readers must use `quorum_audit::journal::load_log` for. Power-loss behaviour is
not rehearsed. Compaction is O(n) (rare). Persist-then-swap ordering is unchanged.
