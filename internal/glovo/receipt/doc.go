// Package receipt is the Glovo write fence and the checks around the
// authoritative approval ledger (mctl-api#989).
//
// The action_approval_requests (aar_) row of a Glovo order is the only
// authority for a physical write. The bridge asks this package, inside its
// permit transaction, whether the write may happen: Fence.PreLock takes the
// #957 section 6b lock levels L1-L4 before the bridge locks the command (L5),
// and Fence.Check recomputes everything from what is written (the payload
// basket, its fingerprint, the intent hash) before it consumes the approval.
//
// Cross-slice notes (task 9):
//   - #957 prepare calls workitems.Store.CreateGlovoApprovalTx under L3 (the
//     order row), in the transaction that creates the order's approval_ref.
//   - #985 uses the workitems Glovo Tx methods (Lock, Reserve, Revoke,
//     MarkGlovoApprovalUnknownTx) and calls MarkGlovoApprovalUnknownTx itself
//     when it cancels a command that never had a permit; it is the only
//     caller of bridge.Store.SetFence, after all six #985 section 7.3
//     preconditions and a nil Ready.
//   - The lock order is the canonical one of #957 section 6b: L1 install
//     (shared), L2 owner (shared), L3 order, L4 aar_, L5 command.
//   - GlovoControlInput carries approval_ref and the basket fingerprint;
//     dispatch compares the fingerprint and answers basket_changed.
//   - The provider writes only the lines of the payload basket (OPEN-989-4).
//
// Nothing in this package opens glovo.Default or installs a fence: with the
// default fence the permit path of the bridge is unchanged.
package receipt
