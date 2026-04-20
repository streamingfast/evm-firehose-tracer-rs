# Sync State: refactor inspector

## Overview

Task is about some refactoring to be done while I reviewed recent insepctor/tracer code.

## Current State

Nothing has been done

## Task list

- All setters like `set_current_call_address_delegates_to` should be moved closed to on_call_enter where it has a relation with
- In the  loop

   ```
   for entry in entries {
            match entry {
                ...
            }
   }
   ```

   Make each case call another method instead of inlining the code to improve readability

    - Each journal entry processed should be logged via firehose_tracer::firehose_debug!("...", ...);


- `if old_balance != new_balance {` move this condition into `on_balance_change` directly, that should apply to all
- `  3. Coinbase reward - computed as gas_used * (effective_gas_price - base_fee) after` this will need to be chain gated as the correct handling on base vs optimism vs ethereum might all be different. Introduce an enum for "ChainProtocol::{Ethereum,Base,Optimism}" and have special handling for each chain (for now Base/Optimism could do nothing and log a big warning).
- This code:

  ```
          if depth == 0 {
            if let Some(account) = context.journal().evm_state().get(&inputs.caller) {
                // Gas buy: sender's balance decreased by gas_limit * effective_gas_price
                let old_balance = account.original_info.balance;
                let new_balance = account.info.balance;
                if old_balance != new_balance {
                    self.tracer.on_balance_change(
                        inputs.caller,
                        old_balance,
                        new_balance,
                        pb::sf::ethereum::r#type::v2::balance_change::Reason::GasBuy,
                    );
                    self.balance_tracker.insert(inputs.caller, new_balance);
                }

                // Nonce bump from deduct_caller
                let new_nonce = account.info.nonce;
                self.tracer
                    .on_nonce_change(inputs.caller, new_nonce - 1, new_nonce);
            }
        }
   ```

   it's repeated mostly as the same thing for call/create, needs to be be moved to a shared helper