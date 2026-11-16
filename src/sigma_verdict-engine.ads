--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Generic SPARK Silver core of the sigma_verdict crate.
--
--  Phase 1 evaluates one detection subset: a single integer equality
--  on EventID plus one text match on CommandLine using
--  contains/startswith/endswith, combined with AND/OR/NOT and the
--  Sigma "1 of"/"all of" selection-group idiom.
--
--  Every modifier-name pair NOT in {bare, contains, startswith,
--  endswith} is a designed-in Unsupported error, never a silent
--  non-match. Wider types (Comparisons, CIDR ranges, wildcards,
--  windash, wide, base64 variants, re) arrive in Phase 2 through the
--  same Modifier_Kind enumeration.

generic
   Max_Field_Length       : Positive;
   Max_Value_Length       : Positive;
   Max_Event_Value_Length : Positive;
   Max_Values_Per_Sel     : Positive;
   Max_Fields_Per_Sel     : Positive;
   Max_Selections         : Positive;
   Max_Event_Fields       : Positive;
   Max_Condition_Nodes    : Positive;
   Max_Modifiers_Per_Field : Positive;
   Max_Pattern_Length     : Positive;
package Sigma_Verdict.Engine with SPARK_Mode is

   --  Phase-1-supported modifiers; the rest of the enumeration is
   --  designed in now so the boundary can classify them as
   --  Unsupported instead of dropping them silently.
   type Modifier_Kind is
     (Mod_None,
      Mod_Contains, Mod_Startswith, Mod_Endswith,
      Mod_Re, Mod_Re_Dotall,
      Mod_Windash, Mod_Wide, Mod_Utf16le, Mod_Utf16be,
      Mod_Base64, Mod_Base64offset,
      Mod_Cased, Mod_All,
      Mod_Cidr, Mod_Gt, Mod_Gte, Mod_Lt, Mod_Lte,
      Mod_Exists, Mod_Fieldref, Mod_Expand,
      Mod_Near, Mod_Wildcard_Star, Mod_Wildcard_Question);

   subtype Supported_Modifier is Modifier_Kind range
     Mod_None .. Mod_Endswith;

   type Modifier_List is private;
   Empty_Modifiers : constant Modifier_List;

   type Expected_Kind is (E_Int, E_Text, E_Text_List);

   --  One field constraint inside a selection, e.g.
   --  "CommandLine|contains: 'whoami'".
   type Field_Constraint is record
      Field     : String (1 .. Max_Field_Length);
      Field_Len : Natural := 0;
      Modifiers : Modifier_List;
      Expected  : Expected_Value (Max_Value_Length, Max_Values_Per_Sel);
   end record;

   type Expected_Value (Max_Len, Max_Items : Positive) is record
      Kind : Expected_Kind := E_Text;
      case Kind is
         when E_Int =>
            Int_Value : Integer := 0;
         when E_Text =>
            Single : Bounded_Text (Max_Len);
         when E_Text_List =>
            List : Bounded_Text_Array (Max_Len, Max_Items);
      end case;
   end record;

   type Selection is record
      Name        : String (1 .. Max_Field_Length);
      Name_Len    : Natural := 0;
      Fields      : Field_Array (Max_Fields_Per_Sel);
      Field_Count : Natural := 0;
   end record;

   type Node_Kind is
     (N_Ref, N_And, N_Or, N_Not, N_One_Of, N_All_Of);

   type Condition_Node is record
      Kind : Node_Kind := N_Ref;
      --  Meaning depends on Kind:
      --    N_Ref          Sel_Index (1-based into Rule.Selections)
      --    N_And/N_Or     Left, Right are node indexes
      --    N_Not          Left is the negated node index
      --    N_One_Of/N_All_Of  Left .. Right span a ref run
      Left      : Natural := 0;
      Right     : Natural := 0;
      Sel_Index : Natural := 0;
   end record;

   --  Event under test: a flat field map. Integer fields carry
   --  EventID; text fields carry CommandLine. Unknown fields and
   --  unknown types are explicit errors, never defaulted.
   type Value_Kind is (V_Int, V_Text, V_Unknown);

   type Event_Value (Max_Len : Positive) is record
      Kind : Value_Kind := V_Unknown;
      case Kind is
         when V_Int =>
            Int_Value : Integer := 0;
         when V_Text =>
            Text_Value : Bounded_Text (Max_Len);
         when V_Unknown =>
            null;
      end case;
   end record;

   type Event_Field is record
      Name  : String (1 .. Max_Field_Length);
      N_Len : Natural := 0;
      Value : Event_Value (Max_Event_Value_Length);
   end record;

   type Event_Record is record
      Fields : Event_Field_Array (Max_Event_Fields);
      Count  : Natural := 0;
   end record;

   type Error_Kind is
     (Error_None,
      Error_Invalid_Rule,     --  bad indexes, empty rule, fuel exhausted
      Error_Unknown_Field,    --  event lacks a field the rule needs
      Error_Type_Mismatch,    --  int rule vs text event or vice versa
      Error_Unsupported_Modifier,
      Error_Unsupported_Condition,  --  near/count or bad of-span
      Error_Too_Complex);           --  capacities exceeded at load time

   type Eval_Result is record
      Matched : Boolean := False;
      Error   : Error_Kind := Error_None;
   end record;

   --  A compiled rule: named selections plus one condition tree.
   --  Root = 0 means "no condition" and is rejected at load time.
   type Compiled_Rule is record
      Selections : Selection_Array (Max_Selections);
      Sel_Count  : Natural := 0;
      Nodes      : Node_Array (Max_Condition_Nodes);
      Node_Count : Natural := 0;
      Root       : Natural := 0;
   end record;

   Empty_Rule : constant Compiled_Rule;

   function Evaluate
     (Rule : Compiled_Rule; Event : Event_Record) return Eval_Result
   with Pre => Rule.Sel_Count <= Max_Selections
               and then Rule.Node_Count <= Max_Condition_Nodes
               and then Event.Count <= Max_Event_Fields;

private

   type Modifier_Array is
     array (1 .. Max_Modifiers_Per_Field) of Modifier_Kind;

   type Modifier_List is record
      Items : Modifier_Array := [others => Mod_None];
      Count : Natural := 0;
   end record;

   Empty_Modifiers : constant Modifier_List :=
     (Items => [others => Mod_None], Count => 0);

   type Bounded_Text (Max_Len : Positive) is record
      Data   : String (1 .. Max_Len) := [others => ' '];
      Length : Natural := 0;
   end record;

   type Bounded_Text_Array (Max_Len, Max_Items : Positive) is record
      Items : array (1 .. Max_Items) of Bounded_Text (Max_Len) :=
        [others => (Max_Len => Max_Len,
                    Data    => [others => ' '],
                    Length  => 0)];
      Count : Natural := 0;
   end record;

   type Field_Array is array (Positive range <>) of Field_Constraint;
   type Selection_Array is array (Positive range <>) of Selection;
   type Node_Array is array (Positive range <>) of Condition_Node;
   type Event_Field_Array is
     array (Positive range <>) of Event_Field;

   Empty_Rule : constant Compiled_Rule :=
     (Selections =>
        [others =>
           (Name        => [others => ' '],
            Name_Len    => 0,
            Fields      =>
              [others =>
                 (Field     => [others => ' '],
                  Field_Len => 0,
                  Modifiers => Empty_Modifiers,
                  Expected  =>
                    (Max_Len   => Max_Value_Length,
                     Max_Items => Max_Values_Per_Sel,
                     Kind      => E_Text,
                     Single    =>
                       (Max_Len => Max_Value_Length,
                        Data    => [others => ' '],
                        Length  => 0))))],
      Sel_Count  => 0,
      Nodes      =>
        [others =>
           (Kind => N_Ref, Left => 0, Right => 0, Sel_Index => 0)],
      Node_Count => 0,
      Root       => 0);

end Sigma_Verdict.Engine;
