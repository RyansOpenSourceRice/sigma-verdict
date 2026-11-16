--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Recommended capacity defaults for Sigma_Verdict.Engine instantiations.
--
--  Rationale: static, stack-resident tables keep the SPARK Silver proof
--  tractable (no heap, no pointers) and make worst-case memory use
--  obvious. Sizes follow the norms established in shacl-ada
--  (Terms.Max_Text_Length 512, Shapes.Max_Shapes 64,
--  Max_Constraints_Per_Shape 16, Eval Max_Violations) and
--  pcapng-in-ada (Max_Comment_Len 512, Max_Name_Len 256):
--  pick the smallest bound that fits the production shape, and let the
--  generic formals grow it per deployment. Overflow is always reported
--  (Too_Complex / Ok = False), never silent truncation.

package Sigma_Verdict.Limits with SPARK_Mode is

   --  Field names such as "EventID" or "CommandLine".
   Default_Field_Length : constant := 128;

   --  Expected scalar values inside a rule (e.g. 'whoami').
   Default_Value_Length : constant := 512;

   --  Event-side values (e.g. a full Windows command line).
   Default_Event_Value_Length : constant := 4096;

   --  List values per field, e.g. CommandLine|contains: ['a', 'b'].
   Default_Values_Per_Sel : constant := 16;

   --  Field constraints ANDed inside one selection.
   Default_Fields_Per_Sel : constant := 4;

   --  Named selections per rule (detection map entries).
   Default_Selections : constant := 16;

   --  Fields carried by one event under test.
   Default_Event_Fields : constant := 16;

   --  Nodes of one compiled condition tree.
   Default_Condition_Nodes : constant := 32;

   --  Modifier chain length per field, e.g. |windash|contains is 2.
   Default_Modifiers_Per_Field : constant := 4;

   --  Raw pattern text kept for Phase 2 matchers (re/wildcard).
   Default_Pattern_Length : constant := 256;

end Sigma_Verdict.Limits;
