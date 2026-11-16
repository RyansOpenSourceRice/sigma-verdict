--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Ready-made Engine instantiation at the recommended Limits.
--  Application code should `with Sigma_Verdict.Defaults;` and use
--  `Defaults.Engine` rather than instantiating the generic directly,
--  unless a deployment needs different capacities (then instantiate
--  Sigma_Verdict.Engine with explicit formals).

with Sigma_Verdict.Engine;
with Sigma_Verdict.Limits;

package Sigma_Verdict.Defaults with SPARK_Mode is

   package Engine is new Sigma_Verdict.Engine
     (Max_Field_Length        => Limits.Default_Field_Length,
      Max_Value_Length        => Limits.Default_Value_Length,
      Max_Event_Value_Length  => Limits.Default_Event_Value_Length,
      Max_Values_Per_Sel      => Limits.Default_Values_Per_Sel,
      Max_Fields_Per_Sel      => Limits.Default_Fields_Per_Sel,
      Max_Selections          => Limits.Default_Selections,
      Max_Event_Fields        => Limits.Default_Event_Fields,
      Max_Condition_Nodes     => Limits.Default_Condition_Nodes,
      Max_Modifiers_Per_Field => Limits.Default_Modifiers_Per_Field,
      Max_Pattern_Length      => Limits.Default_Pattern_Length);

end Sigma_Verdict.Defaults;
