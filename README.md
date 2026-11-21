Morpheus W3-A1 PoC — Provider session approval not bound to its intended user
LumerinDiamond 0x6aBE1d282f72B474E54527D93b979A4f64d3030a on Base, fork block 60239987

Run (one command, from this directory; needs only a public Base RPC, already set in the test):

  forge test --match-contract ApprovalTheftPoC --fork-url https://mainnet.base.org --fork-block-number 60239987 -vvv

Expected result: 1 passed, 0 failed — test_approvalTheft() (gas 1653757).

What the test proves, on the deployed diamond at the pinned block:
  1. The attacker (never the intended user) opens a 10,000 MOR session with a
     provider approval signed for the victim.
  2. The victim's retry with the same approval reverts SessionDuplicateApproval.
  3. The provider is paid 29.218485083885714265 MOR from the funding account.
  4. The attacker recovers the full 10,000 MOR stake (net cost zero).

Setup notes:
  - No privileged accounts. Provider, victim, and attacker are fresh test keys.
  - The funding account is used only as a MOR source via a fork-local prank
    (it never signs anything privileged); it is not an owner, admin, or multisig.
  - forge-std is vendored in lib/ so the test runs from a clean clone with no
    install step. Foundry 1.9.0, solc 0.8.24, optimizer 200 runs.
