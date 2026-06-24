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
    fn is_witness_known(&mut self, _opid: Opid, _witness: &SealWitness<Seal>) -> bool {
        false
    }

    /// Returns a previously verified resolved seal for a known state cell.
    ///
    /// This is only used when a consignment intentionally omits already-known ancestor operations.
    /// Returning `None` preserves the default full-history verification path.
    fn known_seal(&mut self, _addr: CellAddr) -> Option<Seal> {
        None
    }

    /// Detects whether the provided seal definitions are already stored for a known operation.
    ///
    /// Implementations may return `true` only when every provided definition exactly matches
    /// previously accepted data. Returning `false` preserves the default full-history path.
    fn are_seals_known(&mut self, _opid: Opid, _seals: &SmallOrdMap<u16, Seal::Definition>) -> bool {
        false
    }

    /// # Nota bene:
    ///
    /// The method is called only for those operations which are not known (i.e. [`Self::is_known`]
    /// returns `false` for the operation id).
    ///
    /// The method is NOT called for the genesis operation.
    fn apply_operation(&mut self, op: VerifiedOperation);

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
    where
        Self: 'a;

    /// Borrow a `Sync` read-only verification context. It MUST resolve the same memory cells as
    /// [`ContractApi::memory`] for every operation reachable during verification.
    fn verify_context(&self) -> Self::Ctx<'_>;
}

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

    let mut layers = Vec::<Vec<usize>>::new();
    let mut frontier = (0..n).filter(|&i| indegree[i] == 0).collect::<Vec<_>>();
    let mut emitted = 0usize;
    while !frontier.is_empty() {
        frontier.sort_unstable();
        let mut next = Vec::<usize>::new();
        for &i in &frontier {
            emitted += 1;
            for &d in &dependents[i] {
                indegree[d] -= 1;
                if indegree[d] == 0 {
                    next.push(d);
                }
            }
        }
        layers.push(frontier);
        frontier = next;
    }
    // A valid consignment DAG cannot cycle; if it somehow does, fall back to one serial layer
    // so verification still rejects it rather than silently dropping operations.
    if emitted != n {
        return alloc::vec![(0..n).collect::<Vec<usize>>()];
    }
    layers
}

/// Record `err` as the fault to report iff it occurs at an earlier stream index than any fault
/// already seen. `evaluate_parallel` collects faults across all layers instead of short-circuiting,
/// then returns the earliest in stream order — the same error the serial `evaluate` returns (it
/// stops at the first faulting operation in stream order).
#[cfg(feature = "parallel")]
fn record_earliest_fault<Seal: RgbSeal>(
    slot: &mut Option<(usize, VerificationError<Seal>)>,
    idx: usize,
    err: VerificationError<Seal>,
) {
    if slot.as_ref().map_or(true, |(seen, _)| idx < *seen) {
        *slot = Some((idx, err));
    }
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

        while let Some(mut block) = reader
            .read_operation()
            .map_err(|e| VerificationError::Stream(Box::new(e)))?
        {
            // Genesis cannot commit to the contract id since the contract does not exist yet;
            // thus, we have to apply this little trick
            if is_genesis {
                if block.operation.contract_id.to_byte_array() != codex_id.to_byte_array() {
                    return Err(VerificationError::NoCodexCommitment);
                }
                block.operation.contract_id = contract_id;
            }
            let opid = block.operation.opid();

            // If the full operation aux data has already been accepted, the
            // stored seal definitions were validated against this operation
            // before. Unknown or partially known aux data still falls through
            // to the normal subset and witness checks below.
            let known = self.is_known(opid);
            let witness_known = match block.witness.as_ref() {
                Some(witness) if known => self.is_witness_known(opid, witness),
                _ => false,
            };

            if known && witness_known && self.are_seals_known(opid, &block.defined_seals) {
                if !seals.is_empty() {
                    for input in &block.operation.destructible_in {
                        seals.remove(&input.addr);
                    }
                }
                continue;
            }

            // We need to check that all seal definitions strictly match operation-defined destructible cells
            // It is a subset and not an equal set since some seals might be unknown to us:
            // we know their commitment auth token but do not know the definition.
            let reported_is_subset = block.defined_seals.values().all(|seal| {
                let auth = seal.auth_token();
                block
                    .operation
                    .destructible_out
                    .iter()
                    .any(|cell| cell.auth == auth)
            });
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
                    for input in &block.operation.destructible_in {
                        seals.remove(&input.addr);
                    }
                }
            } else {
                for input in &block.operation.destructible_in {
                    let seal = seals
                        .remove(&input.addr)
                        .or_else(|| self.known_seal(input.addr))
                        .ok_or(VerificationError::SealUnknown(input.addr))?;
                    closed_seals.push(seal);
                }
            }

            let operation = if known {
                None
            } else {
                // Verify the operation
                let verified = self
                    .codex()
                    .verify(contract_id, block.operation, self.memory(), self.repo())?;
                Some(verified)
            };

            // This convoluted logic happens since we use a state machine which ensures the client can't lie to
            // the verifier
            // Now we can add operation-defined seals to the set of known seals
            if let Some(witness) = block.witness {
                //  Each witness actually produces its own set of witness-output-based seal sources.
                let pub_id = witness.published.pub_id();

                for (pos, seal) in block.defined_seals.iter() {
                    let addr = CellAddr::new(opid, *pos);
                    let seal = seal.to_src().unwrap_or_else(|| seal.resolve(pub_id));
                    seals.insert(addr, seal);
                }

                if !witness_known {
                    let msg = opid.to_byte_array();
                    witness
                        .verify_seals_closing(&closed_seals, msg.into())
                        .map_err(|e| VerificationError::SealsNotClosed(pub_id, opid, e))?;

                    self.apply_witness(opid, witness);
                }
            } else {
                for (pos, seal) in block.defined_seals.iter() {
                    if let Some(seal) = seal.to_src() {
                        seals.insert(CellAddr::new(opid, *pos), seal);
                    }
                }

                if !closed_seals.is_empty() {
                    return Err(VerificationError::NoWitness(opid));
                }
            }

            if is_genesis {
                is_genesis = false
            } else if let Some(operation) = operation {
                self.apply_operation(operation);
            }

            if !block.defined_seals.is_empty() {
                self.apply_seals(opid, block.defined_seals);
            }
        }

        Ok(())
    }

    /// Experimental topology-parallel variant of [`Self::evaluate`] (spike, feature `parallel`).
    ///
    /// Semantically equivalent to `evaluate` for accepted consignments: operations are grouped
    /// into dependency layers (a topological partition in which same-layer operations never
    /// consume each other's seals or read each other's applied state), each layer's read-only
    /// verification (`Codex::verify` + `verify_seals_closing`) runs in parallel via rayon, and the
    /// side-effecting apply (`seals` map + `apply_*`) runs serially in topological order. The
    /// serial `evaluate` remains the authority; this path is off by default.
    ///
    /// Faults are collected across all layers (not short-circuited) and the earliest in stream
    /// order is returned, matching the serial `evaluate` for invalid consignments too. Seal closing
    /// stays on the serial apply path (its `SealError` witness-error associated types are not
    /// `Send`, so it is never carried across rayon).
    #[cfg(feature = "parallel")]
    #[allow(clippy::result_large_err)]
    fn evaluate_parallel<R: ReadOperation<Seal = Seal>>(&mut self, mut reader: R) -> Result<(), VerificationError<Seal>>
    where
        Self: Sized + ParallelVerifyMemory,
    {
        use rayon::prelude::*;

        let contract_id = self.contract_id();
        let codex_id = self.codex().codex_id();

        // 1) Drain the whole consignment; apply the genesis contract-id fixup to the first op.
        let mut blocks = Vec::<OperationSeals<Seal>>::new();
        let mut is_first = true;
        while let Some(mut block) = reader
            .read_operation()
            .map_err(|e| VerificationError::Stream(Box::new(e)))?
        {
            if is_first {
                if block.operation.contract_id.to_byte_array() != codex_id.to_byte_array() {
                    return Err(VerificationError::NoCodexCommitment);
                }
                block.operation.contract_id = contract_id;
                is_first = false;
            }
            blocks.push(block);
        }
        if blocks.is_empty() {
            return Ok(());
        }

        // 2) Dependency layering (Kahn). Genesis (idx 0) has no deps.
        let opids = blocks
            .iter()
            .map(|b| b.operation.opid())
            .collect::<Vec<_>>();
        let layers = operation_dependency_layers(&blocks);

        // Per-op work carried from the serial pre-pass into parallel verify and serial apply.
        // Side-effecting material for the serial apply phase. The operation itself is NOT kept
        // here: it goes into a separate `Vec<Option<Operation>>` consumed by the parallel verify,
        // so the parallel iterator never borrows `Prep` (hence no `SealWitness: Sync` requirement)
        // and the only thread-shared values are `Operation` + the `Sync` verify context.
        struct Prep<Seal: RgbSeal> {
            idx: usize,
            opid: Opid,
            defined_seals: SmallOrdMap<u16, Seal::Definition>,
            witness: Option<SealWitness<Seal>>,
            closed_seals: Vec<Seal>,
            witness_known: bool,
        }

        let mut seals = BTreeMap::<CellAddr, Seal>::new();
        // Faults are collected (not short-circuited) so the earliest in stream order can be
        // returned, matching the serial `evaluate`.
        let mut earliest_fault: Option<(usize, VerificationError<Seal>)> = None;

        for layer in layers {
            // (a) Serial pre-pass: known checks, subset validation, gather closed seals.
            let mut preps = Vec::<Prep<Seal>>::new();
            // Aligned 1:1 with `preps`: the operation to AluVM-verify (`None` for a known op).
            let mut verify_jobs = Vec::<Option<Operation>>::new();
            for &i in &layer {
                let opid = opids[i];
                let known = self.is_known(opid);
                let witness_known = match blocks[i].witness.as_ref() {
                    Some(witness) if known => self.is_witness_known(opid, witness),
                    _ => false,
                };

                if known && witness_known && self.are_seals_known(opid, &blocks[i].defined_seals) {
                    for input in &blocks[i].operation.destructible_in {
                        seals.remove(&input.addr);
                    }
                    continue;
                }

                let reported_is_subset = blocks[i].defined_seals.values().all(|seal| {
                    let auth = seal.auth_token();
                    blocks[i]
                        .operation
                        .destructible_out
                        .iter()
                        .any(|cell| cell.auth == auth)
                });
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
                    record_earliest_fault(
                        &mut earliest_fault,
                        i,
                        VerificationError::SealsDefinitionMismatch { opid, reported, defined, sources },
                    );
                    continue;
                }

                let mut closed_seals = Vec::<Seal>::new();
                let mut seal_unknown = None;
                if witness_known {
                    for input in &blocks[i].operation.destructible_in {
                        seals.remove(&input.addr);
                    }
                } else {
                    for input in &blocks[i].operation.destructible_in {
                        match seals.remove(&input.addr).or_else(|| self.known_seal(input.addr)) {
                            Some(seal) => closed_seals.push(seal),
                            None => {
                                seal_unknown = Some(input.addr);
                                break;
                            }
                        }
                    }
                }
                if let Some(addr) = seal_unknown {
                    record_earliest_fault(&mut earliest_fault, i, VerificationError::SealUnknown(addr));
                    continue;
                }

                // All immutable borrows of `blocks[i]` above have ended; move the owned pieces out
                // (take instead of clone) so the parallel/apply phases need no extra `Clone` bound.
                verify_jobs.push((!known).then(|| blocks[i].operation.clone()));
                preps.push(Prep {
                    idx: i,
                    opid,
                    defined_seals: core::mem::take(&mut blocks[i].defined_seals),
                    witness: blocks[i].witness.take(),
                    closed_seals,
                    witness_known,
                });
            }

            // (b) Parallel verify (read-only on self): the AluVM script + lock script — the
            //     dominant per-op CPU cost. Single-use-seal closing stays in the serial apply
            //     phase below to avoid plumbing the seal `SealError` (whose witness-error
            //     associated types are not `Send`) across rayon worker threads.
            // A `Sync` read-only verification context borrowed from `&self` is what allows a
            // non-`Sync` contract to verify in parallel: rayon shares `&ctx` across threads while
            // the mutable/DB parts of `self` stay untouched until the serial apply below.
            let codex = self.codex();
            let ctx = self.verify_context();
            let verified: Vec<Option<Result<VerifiedOperation, CallError>>> = verify_jobs
                .into_par_iter()
                .map(|job| job.map(|operation| codex.verify(contract_id, operation, &ctx, &ctx)))
                .collect();
            drop(ctx);

            // (c) Serial apply in topological (stream) order: seal closing + side effects.
            for (prep, op_result) in preps.into_iter().zip(verified) {
                let opid = prep.opid;
                let operation = match op_result {
                    Some(Ok(verified)) => Some(verified),
                    Some(Err(err)) => {
                        record_earliest_fault(&mut earliest_fault, prep.idx, err.into());
                        continue;
                    }
                    None => None,
                };

                if let Some(witness) = prep.witness {
                    let pub_id = witness.published.pub_id();
                    for (pos, seal) in prep.defined_seals.iter() {
                        let addr = CellAddr::new(opid, *pos);
                        let seal = seal.to_src().unwrap_or_else(|| seal.resolve(pub_id));
                        seals.insert(addr, seal);
                    }
                    if !prep.witness_known {
                        let msg = opid.to_byte_array();
                        if let Err(err) = witness.verify_seals_closing(&prep.closed_seals, msg.into()) {
                            record_earliest_fault(
                                &mut earliest_fault,
                                prep.idx,
                                VerificationError::SealsNotClosed(pub_id, opid, err),
                            );
                            continue;
                        }
                        self.apply_witness(opid, witness);
                    }
                } else {
                    for (pos, seal) in prep.defined_seals.iter() {
                        if let Some(seal) = seal.to_src() {
                            seals.insert(CellAddr::new(opid, *pos), seal);
                        }
                    }
                    if !prep.closed_seals.is_empty() {
                        record_earliest_fault(&mut earliest_fault, prep.idx, VerificationError::NoWitness(opid));
                        continue;
                    }
                }

                // Genesis (idx 0) is never applied as an operation, mirroring the serial path.
                if prep.idx != 0 {
                    if let Some(operation) = operation {
                        self.apply_operation(operation);
                    }
                }
                if !prep.defined_seals.is_empty() {
                    self.apply_seals(opid, prep.defined_seals);
                }
            }
        }

        if let Some((_, err)) = earliest_fault {
            return Err(err);
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
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self}")
    }
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
        pub fn new(vec: Vec<OperationSeals<TxoSeal>>) -> Self {
            Self(vec.into_iter())
        }
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
        fn destructible(&self, addr: CellAddr) -> Option<StateCell> {
            self.owned.get(&addr).cloned()
        }
        fn immutable(&self, addr: CellAddr) -> Option<StateValue> {
            self.global.get(&addr).cloned()
        }
    }
    impl LibRepo for TestContract {
        fn get_lib(&self, lib_id: LibId) -> Option<&Lib> {
            self.libs.get(&lib_id)
        }
    }
    impl ContractApi<TxoSeal> for TestContract {
        fn contract_id(&self) -> ContractId {
            self.contract_id
        }
        fn codex(&self) -> &Codex {
            &self.codex
        }
        fn repo(&self) -> &impl LibRepo {
            self
        }
        fn memory(&self) -> &impl Memory {
            self
        }
        fn is_known(&self, opid: Opid) -> bool {
            self.known_ops.contains_key(&opid)
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
        fn destructible(&self, addr: CellAddr) -> Option<StateCell> {
            self.0.destructible(addr)
        }
        fn immutable(&self, addr: CellAddr) -> Option<StateValue> {
            self.0.immutable(addr)
        }
    }
    #[cfg(feature = "parallel")]
    impl LibRepo for TestVerifyCtx<'_> {
        fn get_lib(&self, lib_id: LibId) -> Option<&Lib> {
            self.0.get_lib(lib_id)
        }
    }
    #[cfg(feature = "parallel")]
    impl super::ParallelVerifyMemory for TestContract {
        type Ctx<'a> = TestVerifyCtx<'a>;
        fn verify_context(&self) -> TestVerifyCtx<'_> {
            TestVerifyCtx(self)
        }
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
    fn parallel_equiv_empty() {
        assert_serial_parallel_equiv(TestReader::new(vec![]));
    }

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
        let genesis_op = genesis.to_operation(contract().contract_id);
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
    #[should_panic(
        expected = "unknown seal definition for cell address k7fHvPyBlnM8m1n0QUaqNhB0I8kTwWXmi7nB_ZjTGVc:0."
    )]
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
    #[should_panic(
        expected = "unknown seal definition for cell address k7fHvPyBlnM8m1n0QUaqNhB0I8kTwWXmi7nB_ZjTGVc:0."
    )]
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
