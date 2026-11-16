--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Deterministic Sigma detection evaluator (SPARK Silver core).
--
   --  One generic package holds the whole trusted core so there are no
   --  formal-package dependencies to prove across: AST types, the
   --  Phase 1 matchers (exact/contains/startswith/endswith, ASCII
   --  case-insensitive per the Sigma specification unless `cased`),
   --  the structural flags (`all` conjunction, `exists` presence) and
   --  the condition evaluator (AND/OR/NOT plus "1 of"/"all of").
--
--  The AST deliberately carries the FULL Sigma surface: the complete
--  Modifier_Kind enumeration (including re/wildcard/windash/wide/
--  base64/...) and reserved Phase 2 condition nodes. Anything outside
--  Phase 1 evaluates to an explicit Unsupported error (fail-closed),
--  never to a silent False. See SPECIFICATION.md for the subset table
--  and the Phase 2 plan (Thompson NFA / Pike VM, step-fuelled).
--
--  The core never raises: constructors report Ok = False and Evaluate
--  reports Eval_Error. Integer field comparison uses Integer; larger
--  magnitudes are rejected at the boundary, not wrapped here.

with Sigma_Verdict.Limits;

generic
   Max_Field_Length        : Positive := Limits.Default_Field_Length;
   Max_Value_Length        : Positive := Limits.Default_Value_Length;
   Max_Event_Value_Length  : Positive := Limits.Default_Event_Value_Length;
   Max_Values_Per_Sel      : Positive := Limits.Default_Values_Per_Sel;
   Max_Fields_Per_Sel      : Positive := Limits.Default_Fields_Per_Sel;
   Max_Selections          : Positive := Limits.Default_Selections;
   Max_Event_Fields        : Positive := Limits.Default_Event_Fields;
   Max_Condition_Nodes     : Positive := Limits.Default_Condition_Nodes;
   Max_Modifiers_Per_Field : Positive := Limits.Default_Modifiers_Per_Field;
   Max_Pattern_Length      : Positive := Limits.Default_Pattern_Length;
package Sigma_Verdict.Engine with SPARK_Mode is

   ----------------
   --  Textuals --
   ----------------

   --  Bounded, blank-padded text. Only Data (1 .. Length) is significant.
   --  The predicate pins Length to the buffer so every slice the core
   --  takes is provably in range; only the constructors can build one.
   type Field_Name is record
      Length : Natural := 0;
      Data   : String (1 .. Max_Field_Length) := [others => ' '];
   end record
     with Dynamic_Predicate => Field_Name.Length <= Max_Field_Length;

   type Value_Text is record
      Length : Natural := 0;
      Data   : String (1 .. Max_Value_Length) := [others => ' '];
   end record
     with Dynamic_Predicate => Value_Text.Length <= Max_Value_Length;

   type Event_Text is record
      Length : Natural := 0;
      Data   : String (1 .. Max_Event_Value_Length) := [others => ' '];
   end record
     with Dynamic_Predicate => Event_Text.Length <= Max_Event_Value_Length;

   type Pattern_Text is record
      Length : Natural := 0;
      Data   : String (1 .. Max_Pattern_Length) := [others => ' '];
   end record
     with Dynamic_Predicate => Pattern_Text.Length <= Max_Pattern_Length;

   --  Constructor results: Ok = False means the input exceeded capacity.
   type Field_Result is record
      Ok    : Boolean := False;
      Value : Field_Name;
   end record;

   type Value_Result is record
      Ok    : Boolean := False;
      Value : Value_Text;
   end record;

   type Event_Text_Result is record
      Ok    : Boolean := False;
      Value : Event_Text;
   end record;

   type Pattern_Result is record
      Ok    : Boolean := False;
      Value : Pattern_Text;
   end record;

   function To_Field_Name (S : String) return Field_Result;
   function To_Value_Text (S : String) return Value_Result;
   function To_Event_Text (S : String) return Event_Text_Result;
   function To_Pattern (S : String) return Pattern_Result;

   function Image_Of (F : Field_Name) return String;
   --  Logical image of the significant slice, for contracts only.

   -----------------
   --  Modifiers --
   -----------------

   --  Full Sigma modifier surface (sigmahq.io/docs/basics/modifiers).
   --  Phase 1a evaluates matchers (bare/contains/startswith/endswith),
   --  the case flag (cased), list conjunction (all) and presence
   --  (exists); the rest (including Mod_Unknown, which the boundary
   --  must reject at load) fail closed with Error_Unsupported_Modifier.
   type Modifier_Kind is
     (Mod_None,
      Mod_Contains, Mod_Startswith, Mod_Endswith,
      Mod_Re, Mod_Re_I, Mod_Re_M, Mod_Re_S,
      Mod_Wildcard,
      Mod_Windash,
      Mod_Wide, Mod_UTF16LE, Mod_UTF16BE,
      Mod_Base64, Mod_Base64Offset,
      Mod_Cased,
      Mod_All,
      Mod_Exists,
      Mod_Fieldref,
      Mod_Expand,
      Mod_GT, Mod_GTE, Mod_LT, Mod_LTE,
      Mod_CIDR,
      Mod_Unknown);

   function Is_Supported_Modifier (M : Modifier_Kind) return Boolean is
     (M in Mod_None | Mod_Contains | Mod_Startswith | Mod_Endswith);

   function Parse_Modifier (Token : String) return Modifier_Kind;
   --  Maps one '|' chain element ("contains", "re", "windash", ...);
   --  anything unrecognised yields Mod_Unknown.

   subtype Modifier_Count is Natural range 0 .. Max_Modifiers_Per_Field;
   type Modifier_Array is array (1 .. Max_Modifiers_Per_Field) of Modifier_Kind;

   type Modifier_Set is record
      Count : Modifier_Count := 0;
      Items : Modifier_Array := [others => Mod_None];
   end record;

   function Empty_Modifiers return Modifier_Set is
     ((Count => 0, Items => [others => Mod_None]));

   function Can_Add_Modifier (Set : Modifier_Set) return Boolean is
     (Set.Count < Max_Modifiers_Per_Field);

   procedure Add_Modifier
     (Set : in out Modifier_Set; M : in Modifier_Kind; Ok : out Boolean);
   --  Appends M; Ok = False when the chain is already full.

   function Has_Modifier (Set : Modifier_Set; M : Modifier_Kind) return Boolean;
   --  True iff M occurs anywhere in the chain.

   function Chain_Supported (Set : Modifier_Set) return Boolean;
   --  True iff the chain holds at most one matcher token
   --  (bare/contains/startswith/endswith) plus any combination of the
   --  structural flags (cased/all/exists). Anything else — views,
   --  comparisons, patterns, unknown tokens, or several matchers —
   --  fails closed with Error_Unsupported_Modifier.

   ----------------
   --  Selections --
   ----------------

   type Expected_Kind is (E_Int, E_Text, E_Text_List, E_Int_List, E_Pattern);

   subtype Value_Count is Natural range 0 .. Max_Values_Per_Sel;
   type Value_Text_Array is array (1 .. Max_Values_Per_Sel) of Value_Text;
   type Int_Array is array (1 .. Max_Values_Per_Sel) of Integer;

   type Expected_Value (Kind : Expected_Kind := E_Text) is record
      case Kind is
         when E_Int =>
            Int_Value : Integer := 0;
         when E_Text =>
            Single : Value_Text;
         when E_Text_List =>
            Items : Value_Text_Array;
            Count : Value_Count := 0;
         when E_Int_List =>
            Ints     : Int_Array := [others => 0];
            Int_Count : Value_Count := 0;
         when E_Pattern =>
            Pattern : Pattern_Text;
      end case;
   end record;

   type Field_Constraint is record
      Field     : Field_Name;
      Modifiers : Modifier_Set;
      Expected  : Expected_Value;
   end record;

   subtype Field_Index is Natural range 0 .. Max_Fields_Per_Sel;
   type Constraint_Array is array (1 .. Max_Fields_Per_Sel) of Field_Constraint;

   --  One named selection: all constraints must match (Sigma AND).
   type Selection is record
      Name        : Field_Name;
      Fields      : Constraint_Array;
      Field_Count : Field_Index := 0;
   end record;

   subtype Selection_Count is Natural range 0 .. Max_Selections;
   type Selection_Array is array (1 .. Max_Selections) of Selection;

   function Can_Add_Selection (Sel_Count : Selection_Count) return Boolean is
     (Sel_Count < Max_Selections);

   function Can_Add_Field (Sel : Selection) return Boolean is
     (Sel.Field_Count < Max_Fields_Per_Sel);

   ----------------
   --  Conditions --
   ----------------

   --  N_Near / N_Count reserve the Phase 2 surface; the evaluator
   --  answers them with Error_Unsupported_Condition (fail-closed).
   type Node_Kind is
     (N_Ref, N_Not, N_And, N_Or, N_One_Of, N_All_Of, N_Near, N_Count);

   type Condition_Node (Kind : Node_Kind := N_Ref) is record
      case Kind is
         when N_Ref =>
            Sel_Index : Positive := 1;
         when N_Not =>
            Child : Positive := 1;
         when N_And | N_Or | N_Near =>
            Left  : Positive := 1;
            Right : Positive := 1;
         when N_One_Of | N_All_Of =>
            Prefix : Field_Name;
         when N_Count =>
            Count_Sel : Positive := 1;
            Threshold : Natural := 0;
      end case;
   end record;

   subtype Node_Count_Type is Natural range 0 .. Max_Condition_Nodes;
   type Node_Array is array (1 .. Max_Condition_Nodes) of Condition_Node;

   function Can_Add_Node (Node_Count : Node_Count_Type) return Boolean is
     (Node_Count < Max_Condition_Nodes);

   --  A compiled rule: named selections plus one condition tree.
   --  Root = 0 (or anything above Node_Count) is invalid and makes
   --  Evaluate answer Error_Invalid_Rule instead of raising.
   type Compiled_Rule is record
      Selections : Selection_Array;
      Sel_Count  : Selection_Count := 0;
      Nodes      : Node_Array;
      Node_Count : Node_Count_Type := 0;
      Root       : Natural := 0;
   end record;

   function Empty_Rule return Compiled_Rule;

   -------------
   --  Events --
   -------------

   type Event_Value_Kind is (V_Int, V_Text);

   type Event_Value (Kind : Event_Value_Kind := V_Text) is record
      case Kind is
         when V_Int =>
            Int_Value : Integer := 0;
         when V_Text =>
            Text_Value : Event_Text;
      end case;
   end record;

   type Event_Field is record
      Name  : Field_Name;
      Value : Event_Value;
   end record;

   subtype Event_Field_Count is Natural range 0 .. Max_Event_Fields;
   type Event_Field_Array is array (1 .. Max_Event_Fields) of Event_Field;

   type Event_Record is record
      Fields : Event_Field_Array;
      Count  : Event_Field_Count := 0;
   end record;

   function Can_Add_Event_Field (E : Event_Record) return Boolean is
     (E.Count < Max_Event_Fields);

   ----------------
   --  Evaluation --
   ----------------

   type Eval_Error is
     (Error_None,
      Error_Unsupported_Modifier,
      Error_Unsupported_Condition,
      Error_Invalid_Rule);

   type Eval_Result is record
      Matched : Boolean := False;
      Error   : Eval_Error := Error_None;
   end record;

   --  Selector prefix test used by "1 of X*" / "all of X*".
   function Has_Prefix (Name, Prefix : Field_Name) return Boolean;

   --  Fail-closed: any Unsupported anywhere in the tree yields
   --  (Matched => False, Error => ...) even if another branch matches.
   function Evaluate (Rule : Compiled_Rule; Event : Event_Record) return Eval_Result;

end Sigma_Verdict.Engine;
