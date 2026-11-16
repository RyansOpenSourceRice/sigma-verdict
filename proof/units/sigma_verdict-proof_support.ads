--  SPDX-License-Identifier: Apache-2.0
--
--  Proof-only instantiation of the generic core at minimal capacities.
--  gnatprove analyzes generic bodies once per instance; this tiny
--  instance keeps proof times down while Defaults (in src/) carries
--  the production capacities. Not part of the library build.

with Sigma_Verdict.Engine;

package Sigma_Verdict.Proof_Support is
   package Tiny_Engine is new Engine
     (Max_Field_Length      => 8,
      Max_Value_Length      => 16,
      Max_Event_Value_Length => 32,
      Max_Values_Per_Sel    => 2,
      Max_Fields_Per_Sel    => 2,
      Max_Selections        => 2,
      Max_Event_Fields      => 2,
      Max_Condition_Nodes   => 4,
      Max_Modifiers_Per_Field => 2,
      Max_Pattern_Length    => 16);
end Sigma_Verdict.Proof_Support;
