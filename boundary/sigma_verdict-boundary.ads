--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Boundary loader: YAML text in, Compiled_Rule out.
--
--  Deliberately outside SPARK (adayıml's API is not provable).
--  Contract: every lossy situation — truncation, unknown shape,
--  unsupported modifier, oversized table — is a Load_Error, never
--  silent data loss.

with Sigma_Verdict.Defaults;

package Sigma_Verdict.Boundary with SPARK_Mode => Off is

   package E renames Sigma_Verdict.Defaults.Engine;

   type Load_Error is
     (Load_Ok,
      Load_Empty_Input,
      Load_Overflow,          --  input or table bigger than capacity
      Load_Syntax,            --  adayaml lexer/parser error
      Load_Unknown_Shape,     --  detection/selection/condition missing
      Load_Unknown_Condition, --  condition references nothing known
      Load_Unsupported,       --  modifier or construct for Phase 2
      Load_Too_Complex);      --  rule shape exceeds engine capacities

   procedure Load_Detection
     (YAML_Text : String;
      Rule      : out E.Compiled_Rule;
      Error     : out Load_Error;
      Detail    : out Natural);
   --  Parse one Sigma detection block. Detail carries the adayaml
   --  event index where loading stopped (0 when not applicable).

end Sigma_Verdict.Boundary;
