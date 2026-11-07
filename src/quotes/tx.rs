//! The transaction stage of a quote with a recipient: encode the selected
//! route (Native's arrives encoded), simulate it at the chain head, and attach
//! the transaction and the simulation's findings to the response.

use super::PricedBeforeCheck;
use super::amm::fresh_amm_snapshot;
use super::request::QuoteTerms;
use super::wire::{PositiveSlippageJson, QuoteResponse, TxJson};
use crate::abi::{addrhex, tohex};
use crate::budget::SolverBudget;
use crate::chain::NATIVE;
use crate::config::Config;
use crate::engine::{Engine, Stamped};
use crate::route::Plan;
use crate::rpc::CanonicalBlock;
use crate::settler::{BuiltTx, PositiveSlippage, build_swap_tx_for_profile};
use crate::simulation;
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, ensure};
use std::time::Instant;

/// Fills `resp`'s transaction fields for `recipient`. An AMM route whose
/// simulation fails at a block after the quote's own is handed back to be
/// priced again (`PricedBeforeCheck`), once: `min_block` is 0 on the first
/// attempt.
#[allow(clippy::too_many_arguments)] // the response, the request and the trade it encodes
pub(super) async fn attach_transaction(
    resp: &mut QuoteResponse,
    cfg: &Config,
    engine: &Engine,
    terms: &QuoteTerms,
    recipient: Address,
    prebuilt_native_tx: Option<BuiltTx>,
    stamped: &Stamped,
    snapshot_hash: B256,
    positive_slippage: Option<PositiveSlippage>,
    selected_plan: Option<&Plan>,
    min_amount_out_net: U256,
    deadline: u64,
    budget: &SolverBudget,
    min_block: u64,
) -> anyhow::Result<()> {
    let QuoteTerms {
        token_in,
        token_out,
        amount_in,
        fee_bps,
        identities,
        ..
    } = *terms;
    let snap = &stamped.snap;
    let sender = identities
        .required_from
        .expect("recipient supplies the default sender");
    ensure!(sender != Address::ZERO, "sender must not be zero");
    let native_entry = prebuilt_native_tx.is_some();
    let tx = match prebuilt_native_tx {
        Some(tx) => tx,
        None => {
            budget.checkpoint("transaction encoding")?;
            let fresh_snap = fresh_amm_snapshot(stamped)?;
            let t = Instant::now();
            let tx = build_swap_tx_for_profile(
                cfg.profile,
                fee_bps,
                cfg.fee_receiver,
                positive_slippage,
                fresh_snap,
                selected_plan.expect("AMM plan checked above"),
                token_in,
                token_out,
                amount_in,
                min_amount_out_net,
                recipient,
                deadline,
            )?;
            resp.meta.encode_ms = t.elapsed().as_millis() as u64;
            tx
        }
    };
    budget.checkpoint("transaction simulation")?;
    let t = Instant::now();
    let rpc = engine.rpc();
    let simulation_block = simulation::simulation_block(
        rpc,
        CanonicalBlock {
            number: snap.block,
            hash: snapshot_hash,
            timestamp: stamped.block_timestamp(),
        },
    )
    .await?;
    let report = match Box::pin(simulation::verify(
        rpc,
        &tx,
        sender,
        token_in,
        amount_in,
        simulation_block,
    ))
    .await
    {
        // Only AMM routes are priced again: a second Native firm quote
        // would be spent on a market maker's price that did not move.
        Err(error)
            if min_block == 0
                && !native_entry
                && simulation_block.number > snap.block
                && error
                    .downcast_ref::<simulation::SimulationFailed>()
                    .is_some() =>
        {
            return Err(error.context(PricedBeforeCheck(simulation_block.number)));
        }
        report => report?,
    };
    resp.meta.simulate_ms = t.elapsed().as_millis() as u64;
    budget.checkpoint("transaction simulation")?;
    resp.tx = Some(TxJson {
        required_from: addrhex(sender),
        to: addrhex(tx.to),
        value: tx.value.to_string(),
        data: tohex(&tx.data),
    });
    resp.allowance_target = Some(tx.allowance_target.map(addrhex));
    resp.allowance_holder = Some(addrhex(
        cfg.profile
            .settler
            .context("transaction built without a Settler profile")?
            .allowance_holder,
    ));
    resp.entrypoint = Some(if native_entry {
        "executeWithNativeAuthorization"
    } else {
        "execute"
    });
    resp.authorization_deadline = Some(native_entry.then_some(deadline));
    resp.approval = Some(report.approval);
    resp.simulation = Some(report.simulation);
    resp.issues = Some(report.issues);
    // "" when unset, matching the Julia responses byte-for-byte
    resp.fee_receiver = Some(cfg.fee_receiver.map(addrhex).unwrap_or_default());
    resp.positive_slippage = positive_slippage.map(|positive_slippage| PositiveSlippageJson {
        recipient: addrhex(positive_slippage.recipient),
        token: addrhex(if token_out == NATIVE {
            NATIVE
        } else {
            cfg.profile.erc20_of(token_out)
        }),
        expected_amount: positive_slippage.expected_amount.to_string(),
        max_bps: positive_slippage.max_bps,
    });
    Ok(())
}
