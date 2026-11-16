--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Boundary: loads a Sigma YAML rule into an Engine.Compiled_Rule.
--
--  The YAML parse itself (adayıml, SPARK off) is outside the proof;
--  this package's job is to translate the parsed event stream into
--  core AST values WITHOUT silent loss: over-long strings, unknown
--  modifiers, unknown condition keywords and empty rules all become
--  explicit Load_Error values, never truncated or defaulted data.
--  Integer fields use Integer; magnitudes outside Integer'Range are
--  rejected here, never wrapped in the core.

with Sigma_Verdict.Defaults;

package Sigma_Verdict.Boundary with SPARK_Mode => Off is

   package E renames Sigma_Verdict.Defaults.Engine;

   type Load_Error is
     (Load_Ok,
      Load_YAML_Error,
      Load_Too_Long,
      Load_Too_Many_Selections,
      Load_Too_Many_Fields,
      Load_Too_Many_Values,
      Load_Too_Many_Nodes,
      Load_Too_Many_Modifiers,
       Load_Unknown_Modifier,
       Load_Unknown_Condition,
       Load_Bad_Integer,
       Load_Bad_Value,
       Load_Empty_Rule,
       Load_Internal);

   --  Parse one Sigma rule document (UTF-8 YAML text) into Compiled_Rule.
   --  Only the detection/logsource subset of SPECIFICATION.md is read;
   --  title/id/logsource metadata are accepted and ignored.
   procedure Load_Detection
     (YAML_Text : String;
      Rule      : out E.Compiled_Rule;
      Error     : out Load_Error;
      Detail    : out Natural);
   --  Detail carries the 1-based byte offset of the failure when known,
   --  else 0. Rule is Empty_Rule unless Error = Load_Ok.

end Sigma_Verdict.Boundary;
