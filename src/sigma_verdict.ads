--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Root package of the sigma_verdict crate.
--
--  IN CORE DEVELOPMENT: this library is not yet usable in production
--  tools. Only the Phase 1 subset (see SPECIFICATION.md) evaluates;
--  everything else reports an explicit Unsupported error, never a
--  silent false verdict.

package Sigma_Verdict with SPARK_Mode is

   Major : constant := 0;
   Minor : constant := 1;
   Patch : constant := 0;

end Sigma_Verdict;
