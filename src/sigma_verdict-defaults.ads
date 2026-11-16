--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Production instantiation of the generic engine at the reviewed
--  default capacities (see Sigma_Verdict.Limits).

with Sigma_Verdict.Limits;

package Sigma_Verdict.Defaults with SPARK_Mode is

   package Engine is new Sigma_Verdict.Engine
     (Max_Field_Length        => Sigma_Verdict.Limits.Default_Field_Length,
      Max_Value_Length        => Sigma_Verdict.Limits.Default_Value_Length,
      Max_Event_Value_Length  =>
        Sigma_Verdict.Limits.Default_Event_Value_Length,
      Max_Values_Per_Sel      =>
        Sigma_Verdict.Limits.Default_Values_Per_Sel,
      Max_Fields_Per_Sel      =>
        Sigma_Verdict.Limits.Default_Fields_Per_Sel,
      Max_Selections          => Sigma_Verdict.Limits.Default_Selections,
      Max_Event_Fields        => Sigma_Verdict.Limits.Default_Event_Fields,
      Max_Condition_Nodes     => Sigma_Verdict.Limits.Default_Condition_Nodes,
      Max_Modifiers_Per_Field =>
        Sigma_Verdict.Limits.Default_Modifiers_Per_Field,
      Max_Pattern_Length      => Sigma_Verdict.Limits.Default_Pattern_Length);

   subtype Compiled_Rule is Engine.Compiled_Rule;
   subtype Event_Record is Engine.Event_Record;
   subtype Eval_Result is Engine.Eval_Result;

end Sigma_Verdict.Defaults;
