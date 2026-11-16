--  SPDX-License-Identifier: Apache-2.0
--
--  Proof-support instantiation: small capacities keep solver time
--  bounded while exercising every code path of the generic core.

with Sigma_Verdict.Limits;
with Sigma_Verdict.Engine;

package Sigma_Verdict.Proof_Support with SPARK_Mode is

   package Tiny_Engine is new Sigma_Verdict.Engine
     (Max_Field_Length        => 8,
      Max_Value_Length        => 16,
      Max_Event_Value_Length  => 32,
      Max_Values_Per_Sel      => 2,
      Max_Fields_Per_Sel      => 2,
      Max_Selections          => 2,
      Max_Event_Fields        => 2,
      Max_Condition_Nodes     => 4,
      Max_Modifiers_Per_Field => 2,
      Max_Pattern_Length      => 16);

end Sigma_Verdict.Proof_Support;
