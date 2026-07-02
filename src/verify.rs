// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::{Debug, Formatter};

use amplify::confinement::SmallOrdMap;
use amplify::ByteArray;
#[cfg(feature = "parallel")]
use single_use_seals::ClientSideWitness;
use single_use_seals::{PublishedWitness, SealError, SealWitness};
use ultrasonic::{
    AuthToken, CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid, VerifiedOperation,
};

use crate::{RgbSeal, RgbSealDef, LIB_NAME_RGB};

/// Combination of an operation with operation-defined seals.
///
/// An operation contains only [`AuthToken`]'s, which are commitments to seal definitions.
/// Hence, we have to separately include a full seal definition next to the operation data.
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "Seal::Definition: serde::Serialize + for<'d> serde::Deserialize<'d>, Seal::PubWitness: \
                 serde::Serialize + for<'d> serde::Deserialize<'d>, Seal::CliWitness: serde::Serialize + for<'d> \
                 serde::Deserialize<'d>"
    )
)]
pub struct OperationSeals<Seal: RgbSeal> {
    /// The operation.
    pub operation: Operation,
    /// Seals defined by an operation.
    pub defined_seals: SmallOrdMap<u16, Seal::Definition>,
    /// An optional witness for the closing of the operation input seals.
    pub witness: Option<SealWitness<Seal>>,
}

impl<Seal: RgbSeal> Clone for OperationSeals<Seal>
where
    Seal::PubWitness: Clone,
    Seal::CliWitness: Clone,
{
    fn clone(&self) -> Self {
        Self {
            operation: self.operation.clone(),
            defined_seals: self.defined_seals.clone(),
            witness: self.witness.clone(),
        }
    }
}

/// Provider which reads an operation and its seals from a consignment stream.
pub trait ReadOperation: Sized {
    /// Seal definition type used by operations.
    type Seal: RgbSeal;

    /// Reads an operation and its seals from a consignment stream and initialize the witness
    /// reader.
    fn read_operation(&mut self) -> Result<Option<OperationSeals<Self::Seal>>, impl Error + 'static>;

    /// Reads an operation together with its `opid`, allowing a reader that already computed the
    /// content-addressed commitment during decode to hand it over instead of forcing `evaluate` to
    /// recompute it per op. The default implementation recomputes `opid()` so existing readers keep
    /// working unchanged; `PredecodedOpReader` overrides this to return the opid memoized at
    /// decode.
    ///
    /// Trust note: the returned `opid` must be the reader's own hash of the very operation it
    /// returns (never a value taken off the wire). `evaluate` recomputes and hard-asserts equality
    /// when `RGB_VERIFY_OPID_MEMO_ASSERT` is set, and always recomputes for genesis (whose
    /// `contract_id` is rewritten during verification).
    fn read_operation_with_opid(&mut self) -> Result<Option<(Opid, OperationSeals<Self::Seal>)>, impl Error + 'static> {
        self.read_operation()
            .map(|maybe| maybe.map(|op| (op.operation.opid(), op)))
    }
}

/// API exposed by the contract required for evaluating and verifying the contract state (see
/// [`ContractVerify`]).
///
/// NB: `apply_operation` is called only after `apply_witness`.
pub trait ContractApi<Seal: RgbSeal> {
    /// Returns contract id for the processed contract.
    ///
    /// Called only once during the operation verification.
    fn contract_id(&self) -> ContractId;

    /// Returns a codex against which the contract must be verified.
    ///
    /// Called only once during the operation verification.
    fn codex(&self) -> &Codex;

    /// Returns repository providing script libraries used during the verification.
    ///
    /// Called only once during the operation verification.
    fn repo(&self) -> &impl LibRepo;

    /// Returns a memory implementation providing read access to all the contract state cells,
    /// including immutable and destructible memory.
    fn memory(&self) -> &impl Memory;

    /// Detects whether an operation with a given id is already known as a _valid_ operation for the
    /// ledger.
    ///
    /// The method MUST return `true` for genesis operation.
    fn is_known(&self, opid: Opid) -> bool;

    /// Detects whether a witness for a known operation is already stored and validated.
    ///
    /// Implementations may return `true` only when the exact witness has already been accepted for
    /// `opid`. Returning `false` preserves the default full verification path.
    fn is_witness_known(&mut self, _opid: Opid, _witness: &SealWitness<Seal>) -> bool { false }

    /// Returns a previously verified resolved seal for a known state cell.
    ///
    /// This is only used when a consignment intentionally omits already-known ancestor operations.
    /// Returning `None` preserves the default full-history verification path.
    fn known_seal(&mut self, _addr: CellAddr) -> Option<Seal> { None }

    /// Detects whether the provided seal definitions are already stored for a known operation.
    ///
    /// Implementations may return `true` only when every provided definition exactly matches
    /// previously accepted data. Returning `false` preserves the default full-history path.
    fn are_seals_known(&mut self, _opid: Opid, _seals: &SmallOrdMap<u16, Seal::Definition>) -> bool { false }

    /// # Nota bene:
    ///
    /// The method is called only for those operations which are not known (i.e. [`Self::is_known`]
    /// returns `false` for the operation id).
    ///
    /// The method is NOT called for the genesis operation.
    fn apply_operation(&mut self, op: VerifiedOperation);

    /// Stages outputs from a fully-known operation so later operations in the same consignment can
    /// read already-validated state without re-running operation verification.
    ///
    /// Implementations must treat this as verification-local state. It must not make an already
    /// spent state cell spendable again after the consume finishes.
    fn stage_known_operation(&mut self, _opid: Opid, _operation: &Operation) {}

    /// # Nota bene:
    ///
    /// The method is called for all operations, including known ones, for which the consignment
    /// provides at least single seal definition information (thus, it may be called for the genesis
    /// operation as well).
    fn apply_seals(&mut self, opid: Opid, seals: SmallOrdMap<u16, Seal::Definition>);

    /// # Nota bene:
    ///
    /// The method is called for all operations, including known ones, which have a witness (i.e.,
    /// except genesis or operations with no destroyed state).
    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<Seal>);
}

/// Provides a `Sync`, read-only view of a contract's verification memory and lib repo so that
/// [`ContractVerify::evaluate_parallel`] can share it across rayon worker threads.
///
/// This is what lets a non-`Sync` contract (e.g. one backed by a DB session plus interior-mutable
/// caches) still drive parallel verification: only the immutable verification state is exposed via
/// the borrowed context, never the mutable / DB-backed parts (which stay on the serial path).
#[cfg(feature = "parallel")]
pub trait ParallelVerifyMemory {
    /// A `Sync` read-only verification context borrowed from `&self`.
    type Ctx<'a>: Memory + LibRepo + Sync
    where Self: 'a;

    /// Borrow a `Sync` read-only verification context. It MUST resolve the same memory cells as
    /// [`ContractApi::memory`] for every operation reachable during verification.
    fn verify_context(&self) -> Self::Ctx<'_>;
}

/// Runtime switch for Plan A layer-width diagnostics, cached once. Enabled when
/// `RGB_PARALLEL_VERIFY_DIAG` is `1`/`true`/`on`. Off by default; emits one
/// `rgb_verify_diag` line per parallel consume so a run already on the parallel
/// path can measure DAG layer width without a separate diagnostics build.
#[cfg(feature = "parallel")]
fn parallel_verify_diag_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("RGB_PARALLEL_VERIFY_DIAG")
            .map(|value| {
                let value = value.trim();
                value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
            })
            .unwrap_or(false)
    })
}

/// Release-effective (not `debug_assert`) opt-in: when `RGB_VERIFY_OPID_MEMO_ASSERT` is set,
/// `evaluate`/`evaluate_parallel` recompute `opid()` for every non-genesis op and hard-panic if it
/// differs from the memoized value carried by the reader. Used to certify the opid-memoization path
/// against the recompute path before enabling it in production. Off by default (memoized opid used
/// directly, zero recompute).
fn opid_memo_assert_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("RGB_VERIFY_OPID_MEMO_ASSERT")
            .map(|value| {
                let value = value.trim();
                value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
            })
            .unwrap_or(false)
    })
}

#[cfg(feature = "verify-diagnostics")]
fn verify_diag_enabled() -> bool { true }

#[cfg(all(not(feature = "verify-diagnostics"), feature = "parallel"))]
fn verify_diag_enabled() -> bool { parallel_verify_diag_enabled() }

#[cfg(feature = "parallel")]
fn operation_dependency_layers<Seal: RgbSeal>(blocks: &[OperationSeals<Seal>]) -> Vec<Vec<usize>> {
    // Opids + opid -> stream index.
    let opids = blocks
        .iter()
        .map(|block| block.operation.opid())
        .collect::<Vec<_>>();
    let mut index = BTreeMap::<Opid, usize>::new();
    for (i, opid) in opids.iter().enumerate() {
        index.insert(*opid, i);
    }

    // Edge producer -> consumer for every in-batch input (`destructible_in` addr opid and
    // `immutable_in` opid). Also chain operations that consume the same destructible cell in
    // stream order: even if the producer is already committed, these operations race on the same
    // owned state and must observe each other's serial apply effects.
    let n = blocks.len();
    let mut indegree = alloc::vec![0usize; n];
    let mut dependents = Vec::<Vec<usize>>::new();
    dependents.resize_with(n, Vec::new);
    let mut last_destructible_consumer = BTreeMap::<CellAddr, usize>::new();
    for (i, block) in blocks.iter().enumerate() {
        let mut deps = BTreeSet::<usize>::new();
        for input in &block.operation.destructible_in {
            if let Some(&p) = index.get(&input.addr.opid) {
                if p != i {
                    deps.insert(p);
                }
            }
            if let Some(prev) = last_destructible_consumer.insert(input.addr, i) {
                if prev != i {
                    deps.insert(prev);
                }
            }
        }
        for addr in &block.operation.immutable_in {
            if let Some(&p) = index.get(&addr.opid) {
                if p != i {
                    deps.insert(p);
                }
            }
        }
        for p in deps {
            dependents[p].push(i);
            indegree[i] += 1;
        }
    }

    // Emit only stream-contiguous ready prefixes. A plain Kahn frontier may include a later
    // producer while an earlier, deeper stream branch still blocks stream-order apply; then the
    // next layer's pre-pass would not see the producer's seals/state. Keeping every layer anchored
    // at the next stream index lets the apply queue drain the whole layer before the following
    // pre-pass, without trusting consignments to be breadth-first ordered.
    let mut layers = Vec::<Vec<usize>>::new();
    let mut emitted = alloc::vec![false; n];
    let mut cursor = 0usize;
    while cursor < n {
        let mut layer = Vec::<usize>::new();
        if indegree[cursor] == 0 {
            while cursor < n && indegree[cursor] == 0 {
                layer.push(cursor);
                cursor += 1;
            }
        } else {
            // Preserve serial stream semantics for malformed or non-topological input: evaluate
            // the blocked item in place and let the normal verifier report the first stream error.
            layer.push(cursor);
            cursor += 1;
        }

        for &i in &layer {
            emitted[i] = true;
        }
        for &i in &layer {
            for &d in &dependents[i] {
                if !emitted[d] {
                    indegree[d] = indegree[d].saturating_sub(1);
                }
            }
        }
        layers.push(layer);
    }
    layers
}

/// Main implementation of the contract verification procedure.
///
/// # Nota bene
///
/// This trait cannot be manually implemented; it is always accessible as a blanked implementation
/// for all types implementing [`ContractApi`] trait.
///
/// The purpose of the trait is to prevent overriding of the implementation in client libraries.
pub trait ContractVerify<Seal: RgbSeal>: ContractApi<Seal> {
    /// Evaluate contract state by verifying and applying contract operations coming from a
    /// consignment `reader`.
    fn evaluate<R: ReadOperation<Seal = Seal>>(&mut self, mut reader: R) -> Result<(), VerificationError<Seal>> {
        let contract_id = self.contract_id();
        let codex_id = self.codex().codex_id();

        let mut is_genesis = true;
        let mut seals = BTreeMap::<CellAddr, Seal>::new();

        // P0 diagnostics: cheap per-`evaluate` counters with no graph
        // construction. `verify-diagnostics` keeps the old always-on behavior;
        // normal parallel builds can enable the same line at runtime with
        // `RGB_PARALLEL_VERIFY_DIAG=1`, which lets chaos-test collect serial
        // baselines without a separate diagnostics build.
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let diag_enabled = verify_diag_enabled();
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let diag_started_at = std::time::Instant::now();
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_total_ops = 0usize;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_known_skipped = 0usize;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_verified_ops = 0usize;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_alu_verify_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_seal_close_ops = 0usize;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_closed_seals = 0usize;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_seal_close_ns = 0u128;
        // Residual decomposition (P0): the alu+seal split showed ~96% of `evaluate` is neither
        // AluVM verify nor seal closing. These buckets attribute that residual across the per-op
        // steps every op pays — stream decode, the `is_known`/witness/seals membership checks (paid
        // by the ~89% known ops that early-`continue`), and the `apply_*` writes — so the dominant
        // cost is identifiable without guessing.
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_read_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_known_check_ns = 0u128;
        // `apply_op` = `apply_operation` (ledger/state side, incl. per-op `recompute`);
        // `apply_seal` = `apply_seals` + `apply_witness` (pile side). Split so the ledger-vs-pile
        // share of the dominant `apply` residual is visible.
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_apply_op_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_apply_seal_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_apply_witness_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_apply_seals_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_subset_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_seal_map_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_resolve_ns = 0u128;
        // Per-op `opid()` recompute (content-addressed commitment). Paid by *every* op including the
        // ~95% known-skipped ones, and previously folded into `misc`. Broken out to confirm/quantify
        // it as the dominant `misc` cost.
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_opid_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_pub_id_ns = 0u128;
        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        let mut diag_seal_to_src_ns = 0u128;

        loop {
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            let read_started_at = diag_enabled.then(std::time::Instant::now);
            let next = reader
                .read_operation_with_opid()
                .map_err(|e| VerificationError::Stream(Box::new(e)))?;
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            if let Some(read_started_at) = read_started_at {
                diag_read_ns += read_started_at.elapsed().as_nanos();
            }
            let Some((memo_opid, mut block)) = next else { break };
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            if diag_enabled {
                diag_total_ops += 1;
            }
            // Genesis cannot commit to the contract id since the contract does not exist yet; thus,
            // we have to apply this little trick. Its opid must therefore be recomputed *after* the
            // contract_id rewrite — genesis never trusts the memoized (pre-rewrite) opid.
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            let opid_started_at = diag_enabled.then(std::time::Instant::now);
            let opid = if is_genesis {
                if block.operation.contract_id.to_byte_array() != codex_id.to_byte_array() {
                    return Err(VerificationError::NoCodexCommitment);
                }
                block.operation.contract_id = contract_id;
                block.operation.opid()
            } else {
                if opid_memo_assert_enabled() {
                    let recomputed = block.operation.opid();
                    if recomputed != memo_opid {
                        panic!(
                            "RGB verify opid memo mismatch (non-genesis): memoized {memo_opid} != recomputed \
                             {recomputed}"
                        );
                    }
                }
                memo_opid
            };
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            if let Some(opid_started_at) = opid_started_at {
                diag_opid_ns += opid_started_at.elapsed().as_nanos();
            }

            // If the full operation aux data has already been accepted, the
            // stored seal definitions were validated against this operation
            // before. Unknown or partially known aux data still falls through
            // to the normal subset and witness checks below.
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            let known_check_started_at = diag_enabled.then(std::time::Instant::now);
            let known = self.is_known(opid);
            let witness_known = match block.witness.as_ref() {
                Some(witness) if known => self.is_witness_known(opid, witness),
                _ => false,
            };
            // `&&` short-circuits exactly as before: `are_seals_known` runs only when both prior
            // checks pass. Materialized into a binding only so the membership-check span can close.
            let fully_known = known && witness_known && self.are_seals_known(opid, &block.defined_seals);
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            if let Some(known_check_started_at) = known_check_started_at {
                diag_known_check_ns += known_check_started_at.elapsed().as_nanos();
            }

            if fully_known {
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                if diag_enabled {
                    diag_known_skipped += 1;
                }
                if !seals.is_empty() {
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                    for input in &block.operation.destructible_in {
                        seals.remove(&input.addr);
                    }
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(seal_map_started_at) = seal_map_started_at {
                        diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                    }
                }
                if !is_genesis {
                    self.stage_known_operation(opid, &block.operation);
                }
                continue;
            }

            // We need to check that all seal definitions strictly match operation-defined destructible cells
            // It is a subset and not an equal set since some seals might be unknown to us:
            // we know their commitment auth token but do not know the definition.
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            let subset_started_at = diag_enabled.then(std::time::Instant::now);
            let reported_is_subset = block.defined_seals.values().all(|seal| {
                let auth = seal.auth_token();
                block
                    .operation
                    .destructible_out
                    .iter()
                    .any(|cell| cell.auth == auth)
            });
            #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
            if let Some(subset_started_at) = subset_started_at {
                diag_subset_ns += subset_started_at.elapsed().as_nanos();
            }
            if !reported_is_subset {
                let defined = block
                    .operation
                    .destructible_out
                    .iter()
                    .map(|cell| cell.auth)
                    .collect::<BTreeSet<_>>();
                let reported = block
                    .defined_seals
                    .values()
                    .map(|seal| seal.auth_token())
                    .collect::<BTreeSet<_>>();
                let sources = block
                    .defined_seals
                    .iter()
                    .map(|(pos, seal)| (*pos, seal.to_string()))
                    .collect();
                return Err(VerificationError::SealsDefinitionMismatch { opid, reported, defined, sources });
            }

            // Collect single-use seal closings by the operation
            let mut closed_seals = Vec::<Seal>::new();
            if witness_known {
                if !seals.is_empty() {
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                    for input in &block.operation.destructible_in {
                        seals.remove(&input.addr);
                    }
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(seal_map_started_at) = seal_map_started_at {
                        diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                    }
                }
            } else {
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                for input in &block.operation.destructible_in {
                    let seal = seals
                        .remove(&input.addr)
                        .or_else(|| self.known_seal(input.addr))
                        .ok_or(VerificationError::SealUnknown(input.addr))?;
                    closed_seals.push(seal);
                }
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                if let Some(seal_map_started_at) = seal_map_started_at {
                    diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                }
            }

            let operation = if known {
                None
            } else {
                // Verify the operation
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                let verify_started_at = diag_enabled.then(std::time::Instant::now);
                let verified = self
                    .codex()
                    .verify(contract_id, block.operation, self.memory(), self.repo())?;
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                if let Some(verify_started_at) = verify_started_at {
                    diag_alu_verify_ns += verify_started_at.elapsed().as_nanos();
                    diag_verified_ops += 1;
                }
                Some(verified)
            };

            // This convoluted logic happens since we use a state machine which ensures the client can't lie to
            // the verifier
            // Now we can add operation-defined seals to the set of known seals
            if let Some(witness) = block.witness {
                //  Each witness actually produces its own set of witness-output-based seal sources.
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                let pub_id_started_at = diag_enabled.then(std::time::Instant::now);
                let pub_id = witness.published.pub_id();
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                if let Some(pub_id_started_at) = pub_id_started_at {
                    diag_pub_id_ns += pub_id_started_at.elapsed().as_nanos();
                }

                for (pos, seal) in block.defined_seals.iter() {
                    let addr = CellAddr::new(opid, *pos);
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let to_src_started_at = diag_enabled.then(std::time::Instant::now);
                    let src = seal.to_src();
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(to_src_started_at) = to_src_started_at {
                        diag_seal_to_src_ns += to_src_started_at.elapsed().as_nanos();
                    }
                    let seal = if let Some(seal) = src {
                        seal
                    } else {
                        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                        let resolve_started_at = diag_enabled.then(std::time::Instant::now);
                        let seal = seal.resolve(pub_id);
                        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                        if let Some(resolve_started_at) = resolve_started_at {
                            diag_resolve_ns += resolve_started_at.elapsed().as_nanos();
                        }
                        seal
                    };
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                    seals.insert(addr, seal);
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(seal_map_started_at) = seal_map_started_at {
                        diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                    }
                }

                if !witness_known {
                    let msg = opid.to_byte_array();
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let seal_close_started_at = diag_enabled.then(std::time::Instant::now);
                    witness
                        .verify_seals_closing(&closed_seals, msg.into())
                        .map_err(|e| VerificationError::SealsNotClosed(pub_id, opid, e))?;
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(seal_close_started_at) = seal_close_started_at {
                        diag_seal_close_ns += seal_close_started_at.elapsed().as_nanos();
                        diag_seal_close_ops += 1;
                        diag_closed_seals += closed_seals.len();
                    }

                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let apply_started_at = diag_enabled.then(std::time::Instant::now);
                    self.apply_witness(opid, witness);
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(apply_started_at) = apply_started_at {
                        let elapsed = apply_started_at.elapsed().as_nanos();
                        diag_apply_witness_ns += elapsed;
                        diag_apply_seal_ns += elapsed;
                    }
                }
            } else {
                for (pos, seal) in block.defined_seals.iter() {
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    let to_src_started_at = diag_enabled.then(std::time::Instant::now);
                    let src = seal.to_src();
                    #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                    if let Some(to_src_started_at) = to_src_started_at {
                        diag_seal_to_src_ns += to_src_started_at.elapsed().as_nanos();
                    }
                    if let Some(seal) = src {
                        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                        let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                        seals.insert(CellAddr::new(opid, *pos), seal);
                        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                        if let Some(seal_map_started_at) = seal_map_started_at {
                            diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                        }
                    }
                }

                if !closed_seals.is_empty() {
                    return Err(VerificationError::NoWitness(opid));
                }
            }

            if is_genesis {
                is_genesis = false
            } else if let Some(operation) = operation {
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                let apply_started_at = diag_enabled.then(std::time::Instant::now);
                self.apply_operation(operation);
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                if let Some(apply_started_at) = apply_started_at {
                    diag_apply_op_ns += apply_started_at.elapsed().as_nanos();
                }
            }

            if !block.defined_seals.is_empty() {
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                let apply_started_at = diag_enabled.then(std::time::Instant::now);
                self.apply_seals(opid, block.defined_seals);
                #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
                if let Some(apply_started_at) = apply_started_at {
                    let elapsed = apply_started_at.elapsed().as_nanos();
                    diag_apply_seals_ns += elapsed;
                    diag_apply_seal_ns += elapsed;
                }
            }
        }

        #[cfg(any(feature = "verify-diagnostics", feature = "parallel"))]
        if diag_enabled {
            let total_us = diag_started_at.elapsed().as_micros();
            let alu_verify_us = diag_alu_verify_ns / 1_000;
            let avg_alu_verify_us = if diag_verified_ops > 0 { alu_verify_us / diag_verified_ops as u128 } else { 0 };
            let seal_close_us = diag_seal_close_ns / 1_000;
            let avg_seal_close_us =
                if diag_seal_close_ops > 0 { seal_close_us / diag_seal_close_ops as u128 } else { 0 };
            let read_us = diag_read_ns / 1_000;
            let known_check_us = diag_known_check_ns / 1_000;
            let apply_op_us = diag_apply_op_ns / 1_000;
            let apply_seal_us = diag_apply_seal_ns / 1_000;
            let apply_witness_us = diag_apply_witness_ns / 1_000;
            let apply_seals_us = diag_apply_seals_ns / 1_000;
            let apply_us = apply_op_us + apply_seal_us;
            let subset_us = diag_subset_ns / 1_000;
            let seal_map_us = diag_seal_map_ns / 1_000;
            let resolve_us = diag_resolve_ns / 1_000;
            let opid_us = diag_opid_ns / 1_000;
            let pub_id_us = diag_pub_id_ns / 1_000;
            let seal_to_src_us = diag_seal_to_src_ns / 1_000;
            // Whatever the named buckets do not cover (loop bookkeeping, branching, container work
            // not included in the spans above).
            let misc_us = total_us.saturating_sub(
                alu_verify_us
                    + seal_close_us
                    + read_us
                    + known_check_us
                    + apply_us
                    + subset_us
                    + seal_map_us
                    + resolve_us
                    + opid_us
                    + pub_id_us
                    + seal_to_src_us,
            );
            tracing::debug!(
                target: "rgb_verify_diag",
                path = "serial",
                contract_id = %contract_id,
                total_ops = diag_total_ops,
                known_skipped = diag_known_skipped,
                verified_ops = diag_verified_ops,
                verify_us = alu_verify_us,
                avg_verify_us = avg_alu_verify_us,
                alu_verify_us,
                avg_alu_verify_us,
                seal_close_ops = diag_seal_close_ops,
                closed_seals = diag_closed_seals,
                seal_close_us,
                avg_seal_close_us,
                read_us,
                known_check_us,
                subset_us,
                seal_map_us,
                resolve_us,
                opid_us,
                pub_id_us,
                seal_to_src_us,
                apply_us,
                apply_op_us,
                apply_seal_us,
                apply_witness_us,
                apply_seals_us,
                misc_us,
                total_us,
                "verify serial timing breakdown"
            );
        }

        Ok(())
    }

    /// Experimental topology-parallel variant of [`Self::evaluate`] (spike, feature `parallel`).
    ///
    /// Semantically equivalent to `evaluate` for accepted consignments: operations are grouped
    /// into stream-contiguous dependency layers in which same-layer operations never consume each
    /// other's seals or read each other's applied state, each layer's read-only verification
    /// (`Codex::verify` + `verify_seals_closing`) runs in parallel via rayon, and the
    /// side-effecting apply (`seals` map + `apply_*`) runs serially in stream order. The serial
    /// `evaluate` remains the authority; this path is off by default.
    ///
    /// Faults are queued by stream index and returned only when they become the next stream item to
    /// apply. This preserves serial error order without applying independent later operations after
    /// an earlier stream item fails.
    #[cfg(feature = "parallel")]
    #[allow(clippy::result_large_err)]
    fn evaluate_parallel<R: ReadOperation<Seal = Seal>>(&mut self, mut reader: R) -> Result<(), VerificationError<Seal>>
    where
        Self: Sized + ParallelVerifyMemory,
        Seal: Send,
        Seal::PubWitness: Send,
        Seal::CliWitness: Send,
        <Seal::PubWitness as PublishedWitness<Seal>>::PubId: Send,
        <Seal::PubWitness as PublishedWitness<Seal>>::Error: Send,
        <Seal::CliWitness as ClientSideWitness>::Error: Send,
    {
        use rayon::prelude::*;

        let contract_id = self.contract_id();
        let codex_id = self.codex().codex_id();

        // 1) Drain the whole consignment; apply the genesis contract-id fixup to the first op.
        // Plan A layer-width and timing diagnostics. Gated at runtime by `RGB_PARALLEL_VERIFY_DIAG`
        // (cached once) rather than a compile feature. Read before the block loop so per-op opid
        // acquisition can be timed there.
        let diag_enabled = parallel_verify_diag_enabled();

        let mut blocks = Vec::<OperationSeals<Seal>>::new();
        // Opids carried from the reader (memoized at decode for `PredecodedOpReader`), reused below
        // instead of a second recompute pass. Genesis (idx 0) is recomputed after its contract_id
        // rewrite and never trusts the memoized pre-rewrite opid.
        let mut opids = Vec::<Opid>::new();
        let mut diag_opid_ns = 0u128;
        let mut is_first = true;
        while let Some((memo_opid, mut block)) = reader
            .read_operation_with_opid()
            .map_err(|e| VerificationError::Stream(Box::new(e)))?
        {
            let opid_started_at = diag_enabled.then(std::time::Instant::now);
            let opid = if is_first {
                if block.operation.contract_id.to_byte_array() != codex_id.to_byte_array() {
                    return Err(VerificationError::NoCodexCommitment);
                }
                block.operation.contract_id = contract_id;
                is_first = false;
                block.operation.opid()
            } else {
                if opid_memo_assert_enabled() {
                    let recomputed = block.operation.opid();
                    if recomputed != memo_opid {
                        panic!(
                            "RGB verify opid memo mismatch (non-genesis): memoized {memo_opid} != recomputed \
                             {recomputed}"
                        );
                    }
                }
                memo_opid
            };
            if let Some(opid_started_at) = opid_started_at {
                diag_opid_ns += opid_started_at.elapsed().as_nanos();
            }
            opids.push(opid);
            blocks.push(block);
        }
        if blocks.is_empty() {
            return Ok(());
        }

        // 2) Dependency layering (Kahn). Genesis (idx 0) has no deps.
        let layers = operation_dependency_layers(&blocks);

        // Plan A layer-width diagnostics. Gated at runtime by `RGB_PARALLEL_VERIFY_DIAG`
        // (cached once) rather than a compile feature, so a run that already enables the
        // parallel path via `RGB_PARALLEL_VERIFY` can also surface the Kahn layer-width
        // distribution without a separate diagnostics build. This is the primary signal
        // for Plan A's ROI ceiling: a deep+wide DAG approaches core-count speedup, while a
        // narrow chain (max width ~1) gains little. One line per consume; off by default.
        let mut diag_verified_ops = 0usize;
        let mut diag_known_skipped = 0usize;
        let mut diag_alu_verify_ns = 0u128;
        let mut diag_seal_close_ops = 0usize;
        let mut diag_closed_seals = 0usize;
        let mut diag_seal_close_ns = 0u128;
        let mut diag_known_check_ns = 0u128;
        let mut diag_subset_ns = 0u128;
        let mut diag_seal_map_ns = 0u128;
        let mut diag_resolve_ns = 0u128;
        let mut diag_apply_op_ns = 0u128;
        let mut diag_apply_witness_ns = 0u128;
        let mut diag_apply_seals_ns = 0u128;
        let mut diag_pub_id_ns = 0u128;
        let mut diag_seal_to_src_ns = 0u128;
        if diag_enabled {
            let layer_count = layers.len();
            let max_width = layers.iter().map(|l| l.len()).max().unwrap_or(0);
            let total_ops = blocks.len();
            let avg_width = if layer_count > 0 { total_ops as f64 / layer_count as f64 } else { 0.0 };
            let wide_layers = layers.iter().filter(|l| l.len() > 1).count();
            tracing::debug!(
                target: "rgb_verify_diag",
                path = "parallel",
                kind = "layout",
                contract_id = %contract_id,
                total_ops,
                layers = layer_count,
                max_width,
                avg_width,
                wide_layers,
                "verify parallel layout"
            );
        }
        // Wall-clock span for the timing line below. Started after the layout line so its
        // formatting/IO is excluded, and covers layering-driven verify + serial apply — the
        // span that lines up with the serial path's `total_us` for ROI comparison.
        let diag_started_at = diag_enabled.then(std::time::Instant::now);

        // Per-op work carried from the serial pre-pass into parallel verify and serial apply.
        // Side-effecting material for the serial apply phase. The operation itself is NOT kept
        // here: it goes into a separate `Vec<Option<Operation>>` consumed by the parallel verify,
        // so the parallel iterator never borrows `Prep` (hence no `SealWitness: Sync` requirement)
        // and the only thread-shared values are `Operation` + the `Sync` verify context.
        struct Prep<Seal: RgbSeal> {
            idx: usize,
            opid: Opid,
            defined_seals: SmallOrdMap<u16, Seal::Definition>,
            destructible_inputs: Vec<CellAddr>,
            witness_known: bool,
            has_closed_seals: bool,
        }

        struct SealClosingJob<Seal: RgbSeal> {
            opid: Opid,
            witness: SealWitness<Seal>,
            closed_seals: Vec<Seal>,
            witness_known: bool,
        }

        type PubId<Seal> = <<Seal as single_use_seals::SingleUseSeal>::PubWitness as PublishedWitness<Seal>>::PubId;

        struct Apply<Seal: RgbSeal> {
            prep: Prep<Seal>,
            operation: Option<VerifiedOperation>,
            seal: Option<(SealWitness<Seal>, PubId<Seal>)>,
        }

        enum Ready<Seal: RgbSeal> {
            Apply(Box<Apply<Seal>>),
            Fault(Box<VerificationError<Seal>>),
            Skip {
                opid: Opid,
                operation: Operation,
                destructible_inputs: Vec<CellAddr>,
            },
        }

        let mut seals = BTreeMap::<CellAddr, Seal>::new();
        let mut ready = BTreeMap::<usize, Ready<Seal>>::new();
        let mut next_apply_idx = 0usize;
        for layer in layers {
            // (a) Serial pre-pass: known checks, subset validation, gather closed seals.
            let mut layer_ready = Vec::<(usize, Ready<Seal>)>::new();
            let mut preps = Vec::<Prep<Seal>>::new();
            // Aligned 1:1 with `preps`: the operation to AluVM-verify (`None` for a known op).
            let mut verify_jobs = Vec::<Option<Operation>>::new();
            // Aligned 1:1 with `preps`: the witness/seal-closing work for this op, when present.
            let mut seal_jobs = Vec::<Option<SealClosingJob<Seal>>>::new();
            for &i in &layer {
                let opid = opids[i];
                let known_check_started_at = diag_enabled.then(std::time::Instant::now);
                let known = self.is_known(opid);
                if diag_enabled && known {
                    diag_known_skipped += 1;
                }
                let witness_known = match blocks[i].witness.as_ref() {
                    Some(witness) if known => self.is_witness_known(opid, witness),
                    _ => false,
                };

                if known && witness_known && self.are_seals_known(opid, &blocks[i].defined_seals) {
                    if let Some(known_check_started_at) = known_check_started_at {
                        diag_known_check_ns += known_check_started_at.elapsed().as_nanos();
                    }
                    let destructible_inputs = blocks[i]
                        .operation
                        .destructible_in
                        .iter()
                        .map(|input| input.addr)
                        .collect();
                    layer_ready.push((
                        i,
                        Ready::Skip {
                            opid,
                            operation: blocks[i].operation.clone(),
                            destructible_inputs,
                        },
                    ));
                    continue;
                }
                if let Some(known_check_started_at) = known_check_started_at {
                    diag_known_check_ns += known_check_started_at.elapsed().as_nanos();
                }

                let subset_started_at = diag_enabled.then(std::time::Instant::now);
                let reported_is_subset = blocks[i].defined_seals.values().all(|seal| {
                    let auth = seal.auth_token();
                    blocks[i]
                        .operation
                        .destructible_out
                        .iter()
                        .any(|cell| cell.auth == auth)
                });
                if let Some(subset_started_at) = subset_started_at {
                    diag_subset_ns += subset_started_at.elapsed().as_nanos();
                }
                if !reported_is_subset {
                    let defined = blocks[i]
                        .operation
                        .destructible_out
                        .iter()
                        .map(|cell| cell.auth)
                        .collect::<BTreeSet<_>>();
                    let reported = blocks[i]
                        .defined_seals
                        .values()
                        .map(|seal| seal.auth_token())
                        .collect::<BTreeSet<_>>();
                    let sources = blocks[i]
                        .defined_seals
                        .iter()
                        .map(|(pos, seal)| (*pos, seal.to_string()))
                        .collect();
                    layer_ready.push((
                        i,
                        Ready::Fault(Box::new(VerificationError::SealsDefinitionMismatch {
                            opid,
                            reported,
                            defined,
                            sources,
                        })),
                    ));
                    continue;
                }

                let mut closed_seals = Vec::<Seal>::new();
                let mut seal_unknown = None;
                if !witness_known {
                    let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                    for input in &blocks[i].operation.destructible_in {
                        match seals
                            .get(&input.addr)
                            .cloned()
                            .or_else(|| self.known_seal(input.addr))
                        {
                            Some(seal) => closed_seals.push(seal),
                            None => {
                                seal_unknown = Some(input.addr);
                                break;
                            }
                        }
                    }
                    if let Some(seal_map_started_at) = seal_map_started_at {
                        diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                    }
                }
                if let Some(addr) = seal_unknown {
                    layer_ready.push((i, Ready::Fault(Box::new(VerificationError::SealUnknown(addr)))));
                    continue;
                }

                // All immutable borrows of `blocks[i]` above have ended; move the owned pieces out
                // (take instead of clone) so the parallel/apply phases need no extra `Clone` bound.
                verify_jobs.push((!known).then(|| blocks[i].operation.clone()));
                let has_closed_seals = !closed_seals.is_empty();
                seal_jobs.push(blocks[i].witness.take().map(|witness| SealClosingJob {
                    opid,
                    witness,
                    closed_seals,
                    witness_known,
                }));
                preps.push(Prep {
                    idx: i,
                    opid,
                    defined_seals: core::mem::take(&mut blocks[i].defined_seals),
                    destructible_inputs: blocks[i]
                        .operation
                        .destructible_in
                        .iter()
                        .map(|input| input.addr)
                        .collect(),
                    witness_known,
                    has_closed_seals,
                });
            }

            // (b) Parallel verification. AluVM script verification borrows only the read-only
            // context; single-use seal closing owns its witness job and returns it for serial apply.
            // A `Sync` read-only verification context borrowed from `&self` is what allows a
            // non-`Sync` contract to verify in parallel: rayon shares `&ctx` across threads while
            // the mutable/DB parts of `self` stay untouched until the serial apply below.
            let codex = self.codex();
            let ctx = self.verify_context();
            let (verified, seal_results) = rayon::join(
                || {
                    verify_jobs
                        .into_par_iter()
                        .map(|job| {
                            job.map(|operation| {
                                let verify_started_at = diag_enabled.then(std::time::Instant::now);
                                let result = codex.verify(contract_id, operation, &ctx, &ctx);
                                let verify_ns = verify_started_at
                                    .map(|started_at| started_at.elapsed().as_nanos())
                                    .unwrap_or(0);
                                (result, verify_ns)
                            })
                        })
                        .collect::<Vec<_>>()
                },
                || {
                    seal_jobs
                        .into_par_iter()
                        .map(|job| {
                            job.map(|job| {
                                let pub_id_started_at = diag_enabled.then(std::time::Instant::now);
                                let pub_id = job.witness.published.pub_id();
                                let pub_id_ns = pub_id_started_at
                                    .map(|started_at| started_at.elapsed().as_nanos())
                                    .unwrap_or(0);
                                let closed_seals = job.closed_seals.len();
                                let (err, seal_close_ns) = if job.witness_known {
                                    (None, 0)
                                } else {
                                    let msg = job.opid.to_byte_array();
                                    let seal_close_started_at = diag_enabled.then(std::time::Instant::now);
                                    let err = job
                                        .witness
                                        .verify_seals_closing(&job.closed_seals, msg.into())
                                        .err();
                                    let seal_close_ns = seal_close_started_at
                                        .map(|started_at| started_at.elapsed().as_nanos())
                                        .unwrap_or(0);
                                    (err, seal_close_ns)
                                };
                                (job.witness, pub_id, pub_id_ns, err, seal_close_ns, closed_seals, !job.witness_known)
                            })
                        })
                        .collect::<Vec<_>>()
                },
            );
            drop(ctx);

            // (c) Convert same-layer results into stream-indexed ready items. Faults are queued
            // alongside successful operations, so the drain below can preserve serial error order.
            for ((prep, op_result), seal_result) in preps.into_iter().zip(verified).zip(seal_results) {
                let opid = prep.opid;
                let operation = match op_result {
                    Some((result, verify_ns)) => {
                        if diag_enabled {
                            diag_alu_verify_ns += verify_ns;
                            diag_verified_ops += 1;
                        }
                        match result {
                            Ok(verified) => Some(verified),
                            Err(err) => {
                                layer_ready.push((prep.idx, Ready::Fault(Box::new(err.into()))));
                                continue;
                            }
                        }
                    }
                    None => None,
                };

                let seal = if let Some((
                    witness,
                    pub_id,
                    pub_id_ns,
                    seal_err,
                    seal_close_ns,
                    closed_seals,
                    seal_close_checked,
                )) = seal_result
                {
                    if diag_enabled {
                        diag_pub_id_ns += pub_id_ns;
                    }
                    if diag_enabled && seal_close_checked {
                        diag_seal_close_ns += seal_close_ns;
                        diag_seal_close_ops += 1;
                        diag_closed_seals += closed_seals;
                    }
                    if !prep.witness_known {
                        if let Some(err) = seal_err {
                            layer_ready.push((
                                prep.idx,
                                Ready::Fault(Box::new(VerificationError::SealsNotClosed(pub_id, opid, err))),
                            ));
                            continue;
                        } else {
                            Some((witness, pub_id))
                        }
                    } else {
                        Some((witness, pub_id))
                    }
                } else if prep.has_closed_seals {
                    layer_ready.push((prep.idx, Ready::Fault(Box::new(VerificationError::NoWitness(opid)))));
                    continue;
                } else {
                    None
                };

                layer_ready.push((prep.idx, Ready::Apply(Box::new(Apply { prep, operation, seal }))));
            }

            // (d) Publish successful same-layer results to the stream-order apply queue. All
            // side-effects below are drained only as a contiguous prefix of the original stream, so
            // independent later ops cannot mutate `self` before an earlier faulting op is known.
            for (idx, ready_item) in layer_ready {
                ready.insert(idx, ready_item);
            }

            while let Some(ready_item) = ready.remove(&next_apply_idx) {
                let apply = match ready_item {
                    Ready::Skip {
                        opid,
                        operation,
                        destructible_inputs,
                    } => {
                        let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                        for addr in destructible_inputs {
                            seals.remove(&addr);
                        }
                        if let Some(seal_map_started_at) = seal_map_started_at {
                            diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                        }
                        if next_apply_idx != 0 {
                            self.stage_known_operation(opid, &operation);
                        }
                        next_apply_idx += 1;
                        continue;
                    }
                    Ready::Fault(err) => return Err(*err),
                    Ready::Apply(apply) => *apply,
                };

                let Apply { prep, operation, seal } = apply;
                let opid = prep.opid;
                let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                for addr in prep.destructible_inputs {
                    seals.remove(&addr);
                }
                if let Some(seal_map_started_at) = seal_map_started_at {
                    diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                }

                if let Some((witness, pub_id)) = seal {
                    for (pos, seal) in prep.defined_seals.iter() {
                        let addr = CellAddr::new(opid, *pos);
                        let to_src_started_at = diag_enabled.then(std::time::Instant::now);
                        let src = seal.to_src();
                        if let Some(to_src_started_at) = to_src_started_at {
                            diag_seal_to_src_ns += to_src_started_at.elapsed().as_nanos();
                        }
                        let seal = if let Some(seal) = src {
                            seal
                        } else {
                            let resolve_started_at = diag_enabled.then(std::time::Instant::now);
                            let seal = seal.resolve(pub_id);
                            if let Some(resolve_started_at) = resolve_started_at {
                                diag_resolve_ns += resolve_started_at.elapsed().as_nanos();
                            }
                            seal
                        };
                        let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                        seals.insert(addr, seal);
                        if let Some(seal_map_started_at) = seal_map_started_at {
                            diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                        }
                    }
                    if !prep.witness_known {
                        let apply_started_at = diag_enabled.then(std::time::Instant::now);
                        self.apply_witness(opid, witness);
                        if let Some(apply_started_at) = apply_started_at {
                            diag_apply_witness_ns += apply_started_at.elapsed().as_nanos();
                        }
                    }
                } else {
                    for (pos, seal) in prep.defined_seals.iter() {
                        let to_src_started_at = diag_enabled.then(std::time::Instant::now);
                        let src = seal.to_src();
                        if let Some(to_src_started_at) = to_src_started_at {
                            diag_seal_to_src_ns += to_src_started_at.elapsed().as_nanos();
                        }
                        if let Some(seal) = src {
                            let seal_map_started_at = diag_enabled.then(std::time::Instant::now);
                            seals.insert(CellAddr::new(opid, *pos), seal);
                            if let Some(seal_map_started_at) = seal_map_started_at {
                                diag_seal_map_ns += seal_map_started_at.elapsed().as_nanos();
                            }
                        }
                    }
                    if prep.has_closed_seals {
                        unreachable!("missing witness layer returned before apply");
                    }
                }

                // Genesis (idx 0) is never applied as an operation, mirroring the serial path.
                if prep.idx != 0 {
                    if let Some(operation) = operation {
                        let apply_started_at = diag_enabled.then(std::time::Instant::now);
                        self.apply_operation(operation);
                        if let Some(apply_started_at) = apply_started_at {
                            diag_apply_op_ns += apply_started_at.elapsed().as_nanos();
                        }
                    }
                }
                if !prep.defined_seals.is_empty() {
                    let apply_started_at = diag_enabled.then(std::time::Instant::now);
                    self.apply_seals(opid, prep.defined_seals);
                    if let Some(apply_started_at) = apply_started_at {
                        diag_apply_seals_ns += apply_started_at.elapsed().as_nanos();
                    }
                }
                next_apply_idx += 1;
            }
        }
        if diag_enabled {
            let total_us = diag_started_at
                .map(|started_at| started_at.elapsed().as_micros())
                .unwrap_or(0);
            let alu_verify_us = diag_alu_verify_ns / 1_000;
            let avg_alu_verify_us = if diag_verified_ops > 0 { alu_verify_us / diag_verified_ops as u128 } else { 0 };
            let seal_close_us = diag_seal_close_ns / 1_000;
            let avg_seal_close_us =
                if diag_seal_close_ops > 0 { seal_close_us / diag_seal_close_ops as u128 } else { 0 };
            let known_check_us = diag_known_check_ns / 1_000;
            let subset_us = diag_subset_ns / 1_000;
            let seal_map_us = diag_seal_map_ns / 1_000;
            let resolve_us = diag_resolve_ns / 1_000;
            let apply_op_us = diag_apply_op_ns / 1_000;
            let apply_witness_us = diag_apply_witness_ns / 1_000;
            let apply_seals_us = diag_apply_seals_ns / 1_000;
            let apply_seal_us = apply_witness_us + apply_seals_us;
            let apply_us = apply_op_us + apply_seal_us;
            let opid_us = diag_opid_ns / 1_000;
            let pub_id_us = diag_pub_id_ns / 1_000;
            let seal_to_src_us = diag_seal_to_src_ns / 1_000;
            let misc_us = total_us.saturating_sub(
                alu_verify_us
                    + seal_close_us
                    + known_check_us
                    + subset_us
                    + seal_map_us
                    + resolve_us
                    + opid_us
                    + pub_id_us
                    + seal_to_src_us
                    + apply_us,
            );
            tracing::debug!(
                target: "rgb_verify_diag",
                path = "parallel",
                kind = "timing",
                contract_id = %contract_id,
                total_ops = blocks.len(),
                known_skipped = diag_known_skipped,
                verified_ops = diag_verified_ops,
                verify_us = alu_verify_us,
                avg_verify_us = avg_alu_verify_us,
                alu_verify_us,
                avg_alu_verify_us,
                seal_close_ops = diag_seal_close_ops,
                closed_seals = diag_closed_seals,
                seal_close_us,
                avg_seal_close_us,
                known_check_us,
                subset_us,
                seal_map_us,
                resolve_us,
                opid_us,
                pub_id_us,
                seal_to_src_us,
                apply_us,
                apply_op_us,
                apply_seal_us,
                apply_witness_us,
                apply_seals_us,
                misc_us,
                total_us,
                "verify parallel timing breakdown"
            );
        }
        Ok(())
    }
}

impl<Seal: RgbSeal, C: ContractApi<Seal>> ContractVerify<Seal> for C {}

/// Errors returned from the verification.
#[derive(Display, Error, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: RgbSeal> {
    /// error reading the consignment stream.
    ///
    /// Details: {0}
    Stream(Box<dyn Error>),

    /// genesis does not commit to the codex id; a wrong contract genesis is used.
    NoCodexCommitment,

    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    SealsNotClosed(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

    /// unknown seal definition for cell address {0}.
    SealUnknown(CellAddr),

    /// seals, reported to be defined by the operation {opid}, do match the assignments in the
    /// operation.
    ///
    /// Actual operation seals from the assignments: {defined:#?}
    ///
    /// Reported seals: {reported:#?}
    ///
    /// Sources for the reported seals: {sources:#?}
    #[allow(missing_docs)]
    SealsDefinitionMismatch {
        opid: Opid,
        reported: BTreeSet<AuthToken>,
        defined: BTreeSet<AuthToken>,
        sources: BTreeMap<u16, String>,
    },

    /// Eror returned by the virtual machine script.
    #[from]
    #[display(inner)]
    Vm(CallError),
}

// We need manual implementation since otherwise we get an unneeded `Seal::PubWitness: Debug` bound
impl<Seal: RgbSeal> Debug for VerificationError<Seal> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result { write!(f, "{self}") }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::vec;

    use bp::seals::{TxoSeal, TxoSealExt, WOutpoint, WTxoSeal};
    use bp::{Outpoint, Sats, ScriptPubkey, SeqNo, Tx, TxIn, TxOut, Vout};
    use strict_encoding::StrictDumb;
    use ultrasonic::aluvm::alu::{aluasm, CoreConfig, Lib, LibId, LibSite};
    use ultrasonic::aluvm::FIELD_ORDER_SECP;
    use ultrasonic::{fe256, CodexId, Genesis, Identity, Input, StateCell, StateData, StateValue};

    use super::*;

    #[derive(Clone)]
    struct TestReader(vec::IntoIter<OperationSeals<TxoSeal>>);
    impl ReadOperation for TestReader {
        type Seal = TxoSeal;
        fn read_operation(&mut self) -> Result<Option<OperationSeals<Self::Seal>>, impl Error + 'static> {
            Result::<_, Infallible>::Ok(self.0.next())
        }
    }
    impl TestReader {
        pub fn new(vec: Vec<OperationSeals<TxoSeal>>) -> Self { Self(vec.into_iter()) }
    }

    struct TestContract {
        pub codex: Codex,
        pub contract_id: ContractId,
        pub libs: HashMap<LibId, Lib>,
        pub global: HashMap<CellAddr, StateValue>,
        pub owned: HashMap<CellAddr, StateCell>,
        pub known_ops: BTreeMap<Opid, Operation>,
        pub seal_definitions: BTreeMap<Opid, HashMap<u16, WTxoSeal>>,
        pub witnesses: BTreeMap<Opid, Vec<SealWitness<TxoSeal>>>,
    }
    impl Memory for TestContract {
        fn destructible(&self, addr: CellAddr) -> Option<StateCell> { self.owned.get(&addr).cloned() }
        fn immutable(&self, addr: CellAddr) -> Option<StateValue> { self.global.get(&addr).cloned() }
    }
    impl LibRepo for TestContract {
        fn get_lib(&self, lib_id: LibId) -> Option<&Lib> { self.libs.get(&lib_id) }
    }
    impl ContractApi<TxoSeal> for TestContract {
        fn contract_id(&self) -> ContractId { self.contract_id }
        fn codex(&self) -> &Codex { &self.codex }
        fn repo(&self) -> &impl LibRepo { self }
        fn memory(&self) -> &impl Memory { self }
        fn is_known(&self, opid: Opid) -> bool { self.known_ops.contains_key(&opid) }
        fn is_witness_known(&mut self, opid: Opid, witness: &SealWitness<TxoSeal>) -> bool {
            self.witnesses
                .get(&opid)
                .is_some_and(|witnesses| witnesses.contains(witness))
        }
        fn known_seal(&mut self, addr: CellAddr) -> Option<TxoSeal> {
            self.seal_definitions
                .get(&addr.opid)?
                .get(&addr.pos)?
                .to_src()
        }
        fn are_seals_known(&mut self, opid: Opid, seals: &SmallOrdMap<u16, WTxoSeal>) -> bool {
            let Some(stored) = self.seal_definitions.get(&opid) else {
                return false;
            };
            seals
                .iter()
                .all(|(no, seal)| stored.get(no).is_some_and(|stored| stored == seal))
        }
        fn apply_operation(&mut self, op: VerifiedOperation) {
            let opid = op.opid();
            let op = op.into_operation();
            for (no, inp) in op.immutable_out.iter().enumerate() {
                self.global
                    .insert(CellAddr::new(opid, no as u16), inp.value);
            }
            for (no, inp) in op.destructible_out.iter().enumerate() {
                self.owned.insert(CellAddr::new(opid, no as u16), *inp);
            }
            self.known_ops.insert(opid, op);
        }
        fn stage_known_operation(&mut self, opid: Opid, operation: &Operation) {
            for (no, inp) in operation.immutable_out.iter().enumerate() {
                self.global
                    .insert(CellAddr::new(opid, no as u16), inp.value);
            }
            for (no, inp) in operation.destructible_out.iter().enumerate() {
                self.owned.insert(CellAddr::new(opid, no as u16), *inp);
            }
        }
        fn apply_seals(&mut self, opid: Opid, seals: SmallOrdMap<u16, WTxoSeal>) {
            self.seal_definitions.entry(opid).or_default().extend(seals);
        }
        fn apply_witness(&mut self, opid: Opid, witness: SealWitness<TxoSeal>) {
            self.witnesses.entry(opid).or_default().push(witness);
        }
    }

    #[cfg(feature = "parallel")]
    struct TestVerifyCtx<'a>(&'a TestContract);
    #[cfg(feature = "parallel")]
    impl Memory for TestVerifyCtx<'_> {
        fn destructible(&self, addr: CellAddr) -> Option<StateCell> { self.0.destructible(addr) }
        fn immutable(&self, addr: CellAddr) -> Option<StateValue> { self.0.immutable(addr) }
    }
    #[cfg(feature = "parallel")]
    impl LibRepo for TestVerifyCtx<'_> {
        fn get_lib(&self, lib_id: LibId) -> Option<&Lib> { self.0.get_lib(lib_id) }
    }
    #[cfg(feature = "parallel")]
    impl super::ParallelVerifyMemory for TestContract {
        type Ctx<'a> = TestVerifyCtx<'a>;
        fn verify_context(&self) -> TestVerifyCtx<'_> { TestVerifyCtx(self) }
    }

    fn lib() -> Lib {
        let code = aluasm! {
            stop;
        };
        Lib::assemble(&code).unwrap()
    }

    fn codex() -> Codex {
        let lib_id = lib().lib_id();
        Codex {
            name: tiny_s!("TestCodex"),
            developer: Identity::default(),
            version: default!(),
            features: default!(),
            timestamp: 1732529307,
            field_order: FIELD_ORDER_SECP,
            input_config: CoreConfig::default(),
            verification_config: CoreConfig::default(),
            verifiers: tiny_bmap! {
                0 => LibSite::new(lib_id, 0),
            },
        }
    }

    const SEAL_WOUT: WTxoSeal = WTxoSeal {
        primary: WOutpoint::Wout(Vout::from_u32(0)),
        secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
    };

    const SEAL_1: WTxoSeal = WTxoSeal {
        primary: WOutpoint::Extern(Outpoint::coinbase()),
        secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
    };

    fn genesis() -> Genesis {
        let mut genesis = Genesis::strict_dumb();
        genesis.codex_id = codex().codex_id();
        genesis.immutable_out = small_vec![StateData::new(0u64, 1000u64)];
        genesis.destructible_out = small_vec![StateCell {
            data: StateValue::None,
            auth: SEAL_1.auth_token(),
            lock: None
        }];
        genesis
    }

    fn contract() -> TestContract {
        let lib = lib();
        let lib_id = lib.lib_id();
        let genesis = genesis();
        let genesis_op = genesis.to_operation(ContractId::strict_dumb());
        let genesis_opid = genesis_op.opid();
        TestContract {
            codex: codex(),
            contract_id: ContractId::strict_dumb(),
            libs: map! { lib_id => lib },
            global: none!(),
            owned: map! { CellAddr::new(genesis_opid, 0) => genesis_op.destructible_out[0] },
            known_ops: bmap! { genesis_opid => genesis_op },
            seal_definitions: bmap! { genesis_opid => none!() },
            witnesses: bmap! { genesis_opid => none!() },
        }
    }

    fn operation() -> Operation {
        let genesis = genesis();
        let contract = contract();
        let genesis_op = genesis.to_operation(contract.contract_id);
        let genesis_opid = genesis_op.opid();
        Operation {
            version: default!(),
            contract_id: contract.contract_id,
            call_id: 0,
            nonce: fe256::ZERO,
            witness: StateValue::None,
            destructible_in: small_vec![Input {
                addr: CellAddr::new(genesis_opid, 0),
                witness: StateValue::None
            }],
            immutable_in: Default::default(),
            destructible_out: Default::default(),
            immutable_out: Default::default(),
        }
    }

    /// An input-free operation that only appends immutable state. Distinct `tag`s yield distinct
    /// opids, so several of these form one topological layer (no op depends on another) and have no
    /// witness/seal-closing requirement — ideal for exercising the parallel verify path.
    #[cfg(feature = "parallel")]
    fn standalone_op(tag: u64, contract_id: ContractId) -> Operation {
        Operation {
            version: default!(),
            contract_id,
            call_id: 0,
            nonce: fe256::ZERO,
            witness: StateValue::None,
            destructible_in: Default::default(),
            immutable_in: Default::default(),
            destructible_out: Default::default(),
            immutable_out: small_vec![StateData::new(0u64, tag)],
        }
    }

    #[cfg(feature = "parallel")]
    fn immutable_child_op(parent: Opid, tag: u64, contract_id: ContractId) -> Operation {
        Operation {
            version: default!(),
            contract_id,
            call_id: 0,
            nonce: fe256::ZERO,
            witness: StateValue::None,
            destructible_in: Default::default(),
            immutable_in: small_vec![CellAddr::new(parent, 0)],
            destructible_out: Default::default(),
            immutable_out: small_vec![StateData::new(0u64, tag)],
        }
    }

    fn seal_source_op(tag: u64, contract_id: ContractId) -> Operation {
        Operation {
            version: default!(),
            contract_id,
            call_id: 0,
            nonce: fe256::ZERO,
            witness: StateValue::None,
            destructible_in: Default::default(),
            immutable_in: Default::default(),
            destructible_out: small_vec![StateCell {
                data: StateValue::None,
                auth: SEAL_1.auth_token(),
                lock: None
            }],
            immutable_out: small_vec![StateData::new(0u64, tag)],
        }
    }

    fn seal_consumer_op(source: Opid, contract_id: ContractId) -> Operation {
        Operation {
            version: default!(),
            contract_id,
            call_id: 0,
            nonce: fe256::ZERO,
            witness: StateValue::None,
            destructible_in: small_vec![Input { addr: CellAddr::new(source, 0), witness: StateValue::None }],
            immutable_in: Default::default(),
            destructible_out: Default::default(),
            immutable_out: small_vec![StateData::new(0u64, 99u64)],
        }
    }

    /// Assert that the serial `evaluate` and the parallel `evaluate_parallel` reach byte-identical
    /// ledger state on success, and the same error on failure.
    #[cfg(feature = "parallel")]
    fn assert_serial_parallel_equiv(reader: TestReader) {
        let mut serial = contract();
        let serial_res = serial.evaluate(reader.clone());
        let mut parallel = contract();
        let parallel_res = parallel.evaluate_parallel(reader);

        match (&serial_res, &parallel_res) {
            (Ok(()), Ok(())) => {
                assert_eq!(serial.known_ops, parallel.known_ops, "known_ops diverged");
                assert_eq!(serial.owned, parallel.owned, "owned state diverged");
                assert_eq!(serial.global, parallel.global, "global state diverged");
                assert_eq!(serial.seal_definitions, parallel.seal_definitions, "seal definitions diverged");
                assert_eq!(serial.witnesses, parallel.witnesses, "witnesses diverged");
            }
            (Err(serial_err), Err(parallel_err)) => {
                assert_eq!(serial_err.to_string(), parallel_err.to_string(), "error mismatch");
            }
            _ => panic!("serial and parallel evaluation disagree on success/failure"),
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_equiv_empty() { assert_serial_parallel_equiv(TestReader::new(vec![])); }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_equiv_genesis_only() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        assert_serial_parallel_equiv(TestReader::new(vec![OperationSeals {
            operation: genesis_op,
            defined_seals: none!(),
            witness: None,
        }]));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_equiv_wide_layer() {
        // genesis + several independent input-free ops: one wide topological layer that actually
        // exercises concurrent verification, and must match the serial result exactly.
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let contract_id = contract().contract_id;
        let mut ops = vec![OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None }];
        for tag in 1..=6u64 {
            ops.push(OperationSeals {
                operation: standalone_op(tag, contract_id),
                defined_seals: none!(),
                witness: None,
            });
        }
        assert_serial_parallel_equiv(TestReader::new(ops));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_layers_serialize_shared_destructible_input_consumers() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let first = operation();
        let mut second = operation();
        // Keep the same destructible input but make the operation id distinct.
        second.immutable_out = small_vec![StateData::new(0u64, 42u64)];

        let ops: Vec<OperationSeals<TxoSeal>> = vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation: first, defined_seals: none!(), witness: None },
            OperationSeals { operation: second, defined_seals: none!(), witness: None },
        ];
        let layers = operation_dependency_layers(&ops);

        assert_eq!(layers, vec![vec![0], vec![1], vec![2]]);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_non_bfs_stream_sees_prior_layer_seal_producers() {
        // The stream is a valid topological order, but not breadth-first:
        //
        //   genesis -> chain_1 -> chain_2 -> chain_3
        //          \-> producer -> consumer
        //
        // A plain Kahn frontier would schedule `producer` with `chain_1` but stream-order apply
        // would stall at `chain_2`, leaving `consumer` unable to see the producer seal during the
        // next pre-pass. Stream-contiguous layers force `producer` to apply before `consumer` is
        // prepared, so the parallel path fails like serial (`NoWitness`) instead of `SealUnknown`.
        let genesis = genesis();
        let genesis_op = genesis.to_operation(contract().contract_id);
        let contract_id = contract().contract_id;
        let chain_1 = standalone_op(11, contract_id);
        let chain_2 = immutable_child_op(chain_1.opid(), 12, contract_id);
        let chain_3 = immutable_child_op(chain_2.opid(), 13, contract_id);
        let producer = seal_source_op(21, contract_id);
        let consumer = seal_consumer_op(producer.opid(), contract_id);

        let ops = vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation: chain_1, defined_seals: none!(), witness: None },
            OperationSeals { operation: chain_2, defined_seals: none!(), witness: None },
            OperationSeals { operation: chain_3, defined_seals: none!(), witness: None },
            OperationSeals {
                operation: producer,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals { operation: consumer, defined_seals: none!(), witness: None },
        ];
        assert_eq!(operation_dependency_layers(&ops), vec![vec![0, 1], vec![2], vec![3, 4], vec![5]]);
        assert_serial_parallel_equiv(TestReader::new(ops));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_equiv_seal_unknown_error() {
        // A consuming op with no available seal must fail identically on both paths.
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();
        assert_serial_parallel_equiv(TestReader::new(vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]));
    }

    #[test]
    fn known_skip_stages_outputs_for_later_new_operation() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let contract_id = contract().contract_id;
        let producer = seal_source_op(21, contract_id);
        let producer_opid = producer.opid();
        let consumer = seal_consumer_op(producer_opid, contract_id);
        let known_witness = SealWitness::new(strict_dumb!(), strict_dumb!());

        let mut contract = contract();
        contract.known_ops.insert(producer_opid, producer.clone());
        contract
            .seal_definitions
            .insert(producer_opid, map! { 0 => SEAL_1 });
        contract
            .witnesses
            .insert(producer_opid, vec![known_witness.clone()]);

        let err = contract
            .evaluate(TestReader::new(vec![
                OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
                OperationSeals {
                    operation: producer,
                    defined_seals: small_bmap! { 0 => SEAL_1 },
                    witness: Some(known_witness),
                },
                OperationSeals { operation: consumer, defined_seals: none!(), witness: None },
            ]))
            .unwrap_err();

        assert!(
            err.to_string().contains("no witness known for the operation"),
            "expected verification to pass the staged known output and fail later on missing witness, got: {err}"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_error_does_not_apply_later_ready_op() {
        // `later` has no dependencies, so topology layering can verify it before `bad` faults.
        // Applying through a stream-order ready queue prevents that later op from mutating contract
        // state after the earlier stream item fails.
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let bad = operation();
        let later = standalone_op(42, contract().contract_id);
        let later_opid = later.opid();

        let mut parallel = contract();
        let res = parallel.evaluate_parallel(TestReader::new(vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation: bad, defined_seals: none!(), witness: None },
            OperationSeals { operation: later, defined_seals: none!(), witness: None },
        ]));

        assert!(res.is_err());
        assert!(!parallel.known_ops.contains_key(&later_opid));
        assert!(!parallel.global.contains_key(&CellAddr::new(later_opid, 0)));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_equiv_seal_closing_error() {
        // A provided but invalid witness exercises the parallel seal-closing job and must still
        // report the same error as serial evaluation.
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        assert_serial_parallel_equiv(TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(strict_dumb!(), strict_dumb!())),
            },
        ]));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_equiv_multiple_faults_returns_earliest() {
        // Two same-layer ops with distinct faults (each consumes a different unknown cell). The
        // parallel path collects both but must return the earliest in stream order — exactly the
        // error the serial path returns by stopping at the first faulting op.
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let genesis_opid = genesis.to_operation(contract().contract_id).opid();

        let op_a = operation(); // consumes genesis_opid:0 -> SealUnknown(genesis_opid:0)
        let mut op_b = operation();
        // Different unknown input cell + distinct opid -> independent SealUnknown fault, same layer.
        op_b.destructible_in = small_vec![Input {
            addr: CellAddr::new(genesis_opid, 7),
            witness: StateValue::None,
        }];
        op_b.immutable_out = small_vec![StateData::new(0u64, 99u64)];

        assert_serial_parallel_equiv(TestReader::new(vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation: op_a, defined_seals: none!(), witness: None },
            OperationSeals { operation: op_b, defined_seals: none!(), witness: None },
        ]));
    }

    #[allow(clippy::result_large_err)]
    fn run(reader: TestReader) -> Result<(), VerificationError<TxoSeal>> {
        let mut contract = contract();
        contract.evaluate(reader.clone())?;

        // Check contract values
        let mut ops = bmap! {};
        let mut seals = bmap! {};
        let mut witnesses = bmap! {};
        for entry in reader.0 {
            let opid = entry.operation.opid();
            ops.insert(opid, entry.operation);
            seals.insert(opid, entry.defined_seals.into_iter().collect());
            witnesses.insert(opid, entry.witness.into_iter().collect());
        }

        ops.pop_first();
        let (genesis_opid, genesis_op) = contract.known_ops.first_key_value().unwrap();
        ops.insert(*genesis_opid, genesis_op.clone());
        seals.pop_first();
        let (genesis_opid, definitions) = contract.seal_definitions.first_key_value().unwrap();
        seals.insert(*genesis_opid, definitions.clone());
        witnesses.pop_first();
        let (genesis_opid, definitions) = contract.witnesses.first_key_value().unwrap();
        witnesses.insert(*genesis_opid, definitions.clone());

        assert_eq!(ops, contract.known_ops);
        assert_eq!(seals, contract.seal_definitions);
        assert_eq!(witnesses, contract.witnesses);
        Ok(())
    }

    #[test]
    fn empty() {
        let reader = TestReader::new(vec![]);
        run(reader).unwrap();
    }

    #[test]
    fn genesis_only() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());

        let reader =
            TestReader::new(vec![OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None }]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "genesis does not commit to the codex id; a wrong contract genesis is used.")]
    fn invalid_genesis() {
        let mut genesis = genesis();
        genesis.codex_id = CodexId::from_byte_array([0xAD; 32]);
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());

        let reader =
            TestReader::new(vec![OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None }]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "seals, reported to be defined by the operation \
                               k7fHvPyBlnM8m1n0QUaqNhB0I8kTwWXmi7nB_ZjTGVc, do match the assignments in the \
                               operation.
Actual operation seals from the assignments: {
    AuthToken(
        fe256(
            0x0000141b74832b85ca7bc7e2899cc3e5617a29ac4340f09b105524a6f62bd597,
        ),
    ),
}
Reported seals: {
    AuthToken(
        fe256(
            0x000046c31ad97975e90e4ab2ee247f0e2f39ec8461823023e977cc14bcda14f5,
        ),
    ),
}
Sources for the reported seals: {
    0: \"~:0/00000000000000000000000000000000000000000000000000000000000000000000000000000000\",
}")]
    fn invalid_seals() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());

        let reader = TestReader::new(vec![OperationSeals {
            operation: genesis_op,
            defined_seals: small_bmap! { 0 => WTxoSeal::strict_dumb() },
            witness: None,
        }]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown seal definition for cell address k7fHvPyBlnM8m1n0QUaqNhB0I8kTwWXmi7nB_ZjTGVc:0.")]
    fn seal_unknown() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown seal definition for cell address k7fHvPyBlnM8m1n0QUaqNhB0I8kTwWXmi7nB_ZjTGVc:0.")]
    fn genesis_with_wout() {
        let mut genesis = genesis();
        genesis.destructible_out[0].auth = SEAL_WOUT.auth_token();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_WOUT},
                witness: None,
            },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "no witness known for the operation KAPb7ikgqk_ofCp1fZWm_T6XfKjuCwNf9BlZfPpoR0E.")]
    fn no_witness() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "single-use seals are not closed properly with witness \
                               4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a for operation \
                               KAPb7ikgqk_ofCp1fZWm_T6XfKjuCwNf9BlZfPpoR0E.
Details: seal \
                               0000000000000000000000000000000000000000000000000000000000000000:0/\
                               0000000000000000000000000000000000000000000000000000000000000000:0 is not included in \
                               the public witness 4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a")]
    fn seals_unclosed() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(strict_dumb!(), strict_dumb!())),
            },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "ingle-use seals are not closed properly with witness \
                               1692606e775129a6733b6dc48ec7f5771f8e30d8c5304c0949d36efad2411812 for operation \
                               KAPb7ikgqk_ofCp1fZWm_T6XfKjuCwNf9BlZfPpoR0E.
Details: seal \
                               0000000000000000000000000000000000000000000000000000000000000000:0/\
                               0000000000000000000000000000000000000000000000000000000000000000:0 is not included in \
                               the public witness 1692606e775129a6733b6dc48ec7f5771f8e30d8c5304c0949d36efad2411812")]
    fn not_spending_utxo() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let mut witness = Tx::strict_dumb();
        witness
            .outputs
            .push(TxOut {
                value: Sats::ZERO,
                script_pubkey: ScriptPubkey::op_return(&[]),
            })
            .unwrap();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(witness, strict_dumb!())),
            },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "single-use seals are not closed properly with witness \
                               0520b790b442e9c023e2ea0e0e284fbe60086d64f01037082f19464b44f9642e for operation \
                               KAPb7ikgqk_ofCp1fZWm_T6XfKjuCwNf9BlZfPpoR0E.
Details: seal \
                               0000000000000000000000000000000000000000000000000000000000000000:0/\
                               0000000000000000000000000000000000000000000000000000000000000000:0 is not included in \
                               the public witness 0520b790b442e9c023e2ea0e0e284fbe60086d64f01037082f19464b44f9642e")]
    fn missing_commitment() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let mut witness = Tx::strict_dumb();
        witness
            .inputs
            .push(TxIn {
                prev_output: Outpoint::coinbase(),
                sig_script: none!(),
                sequence: SeqNo::from_consensus_u32(0),
                witness: none!(),
            })
            .unwrap();
        witness
            .outputs
            .push(TxOut {
                value: Sats::ZERO,
                script_pubkey: ScriptPubkey::op_return(&[]),
            })
            .unwrap();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(witness, strict_dumb!())),
            },
        ]);
        run(reader).unwrap();
    }
}
