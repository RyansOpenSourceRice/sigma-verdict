--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Deterministic Sigma detection evaluator (SPARK Silver core).
--
   --  One generic package holds the whole trusted core so there are no
   --  formal-package dependencies to prove across: AST types, the
   --  text matchers (exact/contains/startswith/endswith, ASCII
   --  case-insensitive per the Sigma specification unless `cased`),
   --  the structural flags (`all` conjunction, `exists` presence),
   --  the numeric comparisons, CIDR prefix matching, the P3a NFA
   --  pattern engine (glob with implicit wildcards plus the spec
   --  PCRE subset, executed on a step-fuelled Pike VM), and the
   --  condition evaluator (AND/OR/NOT plus "1 of"/"all of").
--
--  The AST deliberately carries the FULL Sigma surface: the complete
--  Modifier_Kind enumeration and reserved later-phase condition nodes.
--  Anything outside the evaluated subset answers an explicit
--  Unsupported error (fail-closed), never a silent False. See
--  SPECIFICATION.md for the subset table, which names every refused
--  construct as the growing pattern subset is built out.
--
--  The core never raises: constructors report Ok = False and Evaluate
--  reports Eval_Error. Integer field comparison uses Integer; larger
--  magnitudes are rejected at the boundary, not wrapped here. IP
--  parsing and matching live in the standalone Sigma_Verdict.IP seam
--  unit (see DESIGN.md "Library seams"); the core only stores
--  IP_Network values and calls into it. Pattern compilation (glob and
--  regex text to NFA states) lives in the boundary (auditable, SPARK
--  off); the core only executes loader-built programs.

with Sigma_Verdict.IP;
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
    Max_Pattern_Code        : Positive := Limits.Default_Pattern_Code;
    Max_View_Length         : Positive := Limits.Default_View_Length;
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

   --  One derived value view (P1b): the boundary expands view modifiers
   --  (wide/base64/...) into these bounded byte strings and the core
   --  matches over them with the existing linear matchers. The
   --  constructor is the only way to build one, so over-long
   --  derivations fail fast instead of producing unprovable slices.
   type View_Text is record
      Length : Natural := 0;
      Data   : String (1 .. Max_View_Length) := [others => ' '];
   end record
     with Dynamic_Predicate => View_Text.Length <= Max_View_Length;

   type View_Result is record
      Ok    : Boolean := False;
      Value : View_Text;
   end record;

   function To_View_Text (S : String) return View_Result;

   function To_Field_Name (S : String) return Field_Result;
   function To_Value_Text (S : String) return Value_Result;
   function To_Event_Text (S : String) return Event_Text_Result;
   function To_Pattern (S : String) return Pattern_Result;

   function Image_Of (F : Field_Name) return String;
   --  Logical image of the significant slice, for contracts only.

   -----------------
   --  Modifiers --
   -----------------

    --  Full Sigma modifier surface (Sigma specification 2.1.0,
    --  modifiers appendix). Matchers (bare/contains/startswith/
    --  endswith), the case flag (cased), list conjunction (all),
    --  presence (exists), value views (windash, wide/utf16*,
    --  base64*), numeric comparisons (gt/gte/lt/lte), CIDR prefix
    --  matching, and patterns (implicit `*`/`?` globs plus the spec
    --  PCRE subset under `re` with `i`/`m`/`s` subflags) evaluate;
    --  the rest (including Mod_Unknown, which the boundary must
    --  reject at load) fails closed with Error_Unsupported_Modifier.
   type Modifier_Kind is
     (Mod_None,
      Mod_Contains, Mod_Startswith, Mod_Endswith,
      Mod_Re, Mod_Re_I, Mod_Re_M, Mod_Re_S,
      Mod_Wildcard,
      Mod_Windash,
      Mod_Wide, Mod_UTF16LE, Mod_UTF16BE, Mod_UTF16,
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

   function Has_View_Modifier (Set : Modifier_Set) return Boolean;
   --  True iff the chain holds any value-view token (windash,
   --  wide/utf16le/utf16be/utf16, base64/base64offset).

   function View_Token (Set : Modifier_Set) return Modifier_Kind;
   --  First view token in the chain, or Mod_None when there is none.

    function Chain_Supported (Set : Modifier_Set) return Boolean;
    --  True iff the chain holds at most one operator token — one
    --  text matcher (bare/contains/startswith/endswith), one
    --  comparison (gt/gte/lt/lte), one cidr, or one pattern source
    --  (`re` plus any distinct i/m/s subflags, or the reserved
    --  wildcard token) — plus at most one view token, plus flags.
    --  Anchor matchers compose with patterns (contains narrows to a
    --  search, startswith/endswith to one-sided anchoring); anything
    --  else mixed with an operator fails closed: several matchers,
    --  several pattern sources, patterns with views/comparisons/
    --  cidr, comparisons/cidr with anything but `all`, `cased`
    --  against `re|i`. Unknown tokens always fail closed.

    function Comparison_Of (Set : Modifier_Set) return Modifier_Kind;
    --  First comparison token in the chain, or Mod_None.

    function Has_Re_Modifier (Set : Modifier_Set) return Boolean;
    --  True iff the chain holds any `re`-class token (re itself or
    --  one of the i/m/s subflags, which each imply `re`). Decides
    --  regex compilation in the boundary; a bare i/m/s token IS a
    --  regex request, never a glob flag.

    function Has_Pattern_Modifier (Set : Modifier_Set) return Boolean;
    --  True iff the chain holds any pattern-class token (re-class
    --  or the reserved Mod_Wildcard).

   --------------------------------
   --  Derived value views (P1b) --
   --------------------------------

   --  base64offset fans one value into exactly three alternatives.
   Max_View_Alternatives : constant := 3;
   type Offset_Alts is array (1 .. Max_View_Alternatives) of View_Text;

   --  windash expands at most three dash occurrences per value
   --  (pySigma SigmaWindowsDashModifier.max_expanded_dashes).
   Max_Dash_Places : constant := 3;
   subtype Dash_Count is Natural range 0 .. Max_Dash_Places;
   type Dash_Pos_Array is array (1 .. Max_Dash_Places) of Natural;

   --  One single-alternative derived view: either boundary-derived
   --  bytes (wide/utf16/base64, matched instead of the raw needle)
   --  or a windash dash mask over the raw needle (1-based positions;
   --  Dash_N > 0 requires Mod_Windash). Alternatives and dashes never
   --  mix. Neither set means "match the raw needle".
   type Single_View is record
      Has_Alt : Boolean := False;
      Alt     : View_Text :=
        (Length => 0, Data => [others => ' ']);
      Dash_N  : Dash_Count := 0;
      Dash_At : Dash_Pos_Array := [others => 0];
   end record;

   type Single_View_Array is
     array (1 .. Max_Values_Per_Sel) of Single_View;

    --------------------------------
    --  Compiled patterns (P3a) --
    --------------------------------

    --  Thompson NFA bytecode. The boundary compiles glob and regex
    --  text into this code; the core Pike VM only executes it, so the
    --  proven TCB never parses pattern syntax. Variable-length code
    --  in a fixed buffer (not a state-record table) keeps sixteen
    --  list programs stack-resident beside the rule.
    --
    --  Layout, all offsets absolute 1-based code positions stored
    --  big-endian in two bytes:
    --    LIT c        : match literal c (folded iff program Fold)
    --    ANY / ANY_NL : match any char (ANY excludes LF)
    --    CLS a b      : match a..b (empty iff a > b)
    --    NCLS a b     : match any char outside a..b (LF included)
    --    SPLIT t1 t2  : epsilon to t1 and t2
    --    JMP t        : epsilon to t
    --    BEGIN        : epsilon to next iff at text start
    --                   (or line start iff Multi_Line)
    --    END          : epsilon to next iff at text end, before a
    --                   final LF, or at a line end iff Multi_Line
    --    MATCH        : accepting state (1 byte, no operands)
    OC_Lit   : constant Character := Character'Val (1);
    OC_Any   : constant Character := Character'Val (2);
    OC_Any_NL : constant Character := Character'Val (3);
    OC_Cls   : constant Character := Character'Val (4);
    OC_NCls  : constant Character := Character'Val (5);
    OC_Split : constant Character := Character'Val (6);
    OC_Jmp   : constant Character := Character'Val (7);
    OC_Begin : constant Character := Character'Val (8);
    OC_End   : constant Character := Character'Val (9);
    OC_Match : constant Character := Character'Val (10);
    OC_Dead  : constant Character := Character'Val (11);
    --  OC_Dead is never emitted by the compiler. The VM decodes
    --  out-of-range stack slots (stale entries, hand-built garbage)
    --  as OC_Dead, which matches no branch and is ignored: removing
    --  edges cannot create a match.

    subtype Pattern_Code_Length is Natural range 0 .. Max_Pattern_Code;
    type Pattern_Code_Array is array (1 .. Max_Pattern_Code) of Character;

    --  One loader-built NFA program. Execution starts at code
    --  position 1. Anchors come from the chain's matcher token
    --  (bare anchors both ends, contains neither,
    --  startswith/endswith one side); `re` without a matcher token
    --  searches. Fold selects case-insensitive matching (Sigma
    --  default, or `re|i`); Multi_Line makes ^/$ per-line (`re|m`).
    --  Length = 0 never leaves the loader and is rejected as an
    --  invalid rule; every jump target is checked on execution, so
    --  hand-built garbage fails closed instead of mis-indexing.
    type NFA_Program is record
       Code         : Pattern_Code_Array := [others => Character'Val (0)];
       Length       : Pattern_Code_Length := 0;
       Fold         : Boolean := False;
       Multi_Line   : Boolean := False;
       Anchor_Start : Boolean := True;
       Anchor_End   : Boolean := True;
    end record;

    function Valid_Program (Prog : NFA_Program) return Boolean is
      (Prog.Length >= 1);
    --  Loader invariant for one program: non-empty code. Internal
    --  validity (known opcodes, in-range targets) is enforced per
    --  access by the VM; anything else fails closed.

    ----------------
    --  Selections --
    ----------------

    type Expected_Kind is
      (E_Int, E_Text, E_Text_List, E_Int_List, E_Pattern,
       E_Pattern_List,
       E_CIDR, E_CIDR_List);

   subtype Value_Count is Natural range 0 .. Max_Values_Per_Sel;
    type Value_Text_Array is array (1 .. Max_Values_Per_Sel) of Value_Text;
    type Int_Array is array (1 .. Max_Values_Per_Sel) of Integer;
    type IP_Network_Array is
      array (1 .. Max_Values_Per_Sel) of Sigma_Verdict.IP.IP_Network;
    type Pattern_Text_Array is
      array (1 .. Max_Values_Per_Sel) of Pattern_Text;
    type NFA_Program_Array is
      array (1 .. Max_Values_Per_Sel) of NFA_Program;

   --  All derived views of one field constraint, parallel to the
   --  text values: E_Text uses Items (1) when Count = 1 (or Offset
   --  when the view is base64offset, which requires a single value);
   --  an E_Text_List with N items uses Items (1 .. N) when
   --  Count = N; otherwise Count is 0 and the raw needles match.
   --  Nested so future view changes never touch field aggregates:
   --  `Views => (others => <>)` stays valid.
   type Field_Views is record
      Items      : Single_View_Array := [others => <>];
      Offset     : Offset_Alts :=
        [others => (Length => 0, Data => [others => ' '])];
      Has_Offset : Boolean := False;
      Count      : Value_Count := 0;
   end record;

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
             Prog    : NFA_Program;
          when E_Pattern_List =>
             Pat_Items : Pattern_Text_Array;
             Pat_Progs : NFA_Program_Array;
             Pat_Count : Value_Count := 0;
         when E_CIDR =>
            Net : Sigma_Verdict.IP.IP_Network;
         when E_CIDR_List =>
            Nets      : IP_Network_Array := [others => <>];
            Net_Count : Value_Count := 0;
      end case;
   end record;

   type Field_Constraint is record
      Field     : Field_Name;
      Modifiers : Modifier_Set;
      Expected  : Expected_Value;
      --  Boundary-derived views (P1b). Defaults keep every existing
      --  aggregate compiling: pass `Views => (others => <>)`.
      Views     : Field_Views := (others => <>);
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

    --  N_Near / N_Count reserve the later-phase surface (P4/P5);
    --  the evaluator answers them with Error_Unsupported_Condition
    --  (fail-closed).
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
