--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Body of the deterministic Sigma detection evaluator.
--
--  All three matchers are linear scans with no recursion, no access
--  types and no exceptions; Eval_Node is the only recursion and it
--  carries an explicit Fuel counter with a Decreases contract so the
--  termination proof is by fuel, not by tree shape. Every load-time
--  rejection lives in the boundary; here every unknown surface
--  (Mod_Unknown, N_Near/N_Count, out-of-range references) maps to an
--  explicit Error_* result, never to False.

package body Sigma_Verdict.Engine with SPARK_Mode is

   ----------------
   --  Textuals --
   ----------------

   function To_Field_Name (S : String) return Field_Result is
   begin
      if S'Length > Max_Field_Length then
         return (Ok => False, Value => <>);
      end if;
      declare
         R : Field_Result := (Ok => True, Value => <>);
      begin
         R.Value.Length := S'Length;
         if S'Length > 0 then
            R.Value.Data (1 .. S'Length) := S;
         end if;
         return R;
      end;
   end To_Field_Name;

   function To_Value_Text (S : String) return Value_Result is
   begin
      if S'Length > Max_Value_Length then
         return (Ok => False, Value => <>);
      end if;
      declare
         R : Value_Result := (Ok => True, Value => <>);
      begin
         R.Value.Length := S'Length;
         if S'Length > 0 then
            R.Value.Data (1 .. S'Length) := S;
         end if;
         return R;
      end;
   end To_Value_Text;

   function To_Event_Text (S : String) return Event_Text_Result is
   begin
      if S'Length > Max_Event_Value_Length then
         return (Ok => False, Value => <>);
      end if;
      declare
         R : Event_Text_Result := (Ok => True, Value => <>);
      begin
         R.Value.Length := S'Length;
         if S'Length > 0 then
            R.Value.Data (1 .. S'Length) := S;
         end if;
         return R;
      end;
   end To_Event_Text;

   function To_Pattern (S : String) return Pattern_Result is
   begin
      if S'Length > Max_Pattern_Length then
         return (Ok => False, Value => <>);
      end if;
      declare
         R : Pattern_Result := (Ok => True, Value => <>);
      begin
         R.Value.Length := S'Length;
         if S'Length > 0 then
            R.Value.Data (1 .. S'Length) := S;
         end if;
         return R;
      end;
   end To_Pattern;

   function Image_Of (F : Field_Name) return String is
     (if F.Length = 0 then "" else F.Data (1 .. F.Length));

   function To_Lower_Char (C : Character) return Character is
     (if C in 'A' .. 'Z'
      then Character'Val (Character'Pos (C) + 32)
      else C);

   function Images_Equal (A : Field_Name; S : String) return Boolean is
      (A.Length = S'Length
       and then (for all I in 1 .. A.Length =>
                    A.Data (I) = S (S'First + I - 1)));

   function Has_Prefix (Name, Prefix : Field_Name) return Boolean is
   begin
      if Prefix.Length = 0 then
         return True;
      end if;
      if Name.Length < Prefix.Length then
         return False;
      end if;
      for I in 1 .. Prefix.Length loop
         if Name.Data (I) /= Prefix.Data (I) then
            return False;
         end if;
      end loop;
      return True;
   end Has_Prefix;

   -----------------
   --  Modifiers --
   -----------------

   function Modifier_Image (M : Modifier_Kind) return String is
     (case M is
        when Mod_None       => "",
        when Mod_Contains   => "contains",
        when Mod_Startswith => "startswith",
        when Mod_Endswith   => "endswith",
        when Mod_Re         => "re",
        when Mod_Re_I       => "re/i",
        when Mod_Re_M       => "re/m",
        when Mod_Re_S       => "re/s",
        when Mod_Wildcard   => "windash",
        when Mod_Windash    => "windash-alias",
        when Mod_Wide       => "wide",
        when Mod_UTF16LE    => "utf16le",
        when Mod_UTF16BE    => "utf16be",
        when Mod_Base64     => "base64",
        when Mod_Base64Offset => "base64offset",
        when Mod_Cased      => "cased",
        when Mod_All        => "all",
        when Mod_Exists     => "exists",
        when Mod_Fieldref   => "fieldref",
        when Mod_Expand     => "expand",
        when Mod_GT         => "gt",
        when Mod_GTE        => "gte",
        when Mod_LT         => "lt",
        when Mod_LTE        => "lte",
        when Mod_CIDR       => "cidr",
        when Mod_Unknown    => "?");

   function Parse_Modifier (Token : String) return Modifier_Kind is
      P_Norm   : String (1 .. Token'Length);
      P_Image  : Field_Name;
      P_Result : Field_Result;
   begin
      for I in Token'Range loop
         P_Norm (I - Token'First + 1) := To_Lower_Char (Token (I));
      end loop;
      P_Result := To_Field_Name (P_Norm);
      if P_Result.Ok then
         P_Image := P_Result.Value;
         for M in Modifier_Kind loop
            declare
               Expected_Image : constant String := Modifier_Image (M);
            begin
               if Images_Equal (P_Image, Expected_Image) then
                  return M;
               end if;
            end;
         end loop;
      end if;
      return Mod_Unknown;
   end Parse_Modifier;

   procedure Add_Modifier
     (Set : in out Modifier_Set; M : in Modifier_Kind; Ok : out Boolean)
   is
   begin
      if Set.Count >= Max_Modifiers_Per_Field then
         Ok := False;
         return;
      end if;
      Set.Count := Set.Count + 1;
      Set.Items (Set.Count) := M;
      Ok := True;
   end Add_Modifier;

   function Chain_Supported (Set : Modifier_Set) return Boolean is
   begin
      for I in 1 .. Set.Count loop
         if not Is_Supported_Modifier (Set.Items (I)) then
            return False;
         end if;
      end loop;
      return True;
   end Chain_Supported;

   ----------------
   --  Matching --
   ----------------

   --  All three matchers fold ASCII case ('A'..'Z' + 32) inline, per
   --  the Sigma specification: matching is case-insensitive unless
   --  the `cased` modifier (Phase 2, Unsupported) is present.

   function Match_Exact (V : Value_Text; E : Event_Value) return Boolean is
   begin
      if E.Kind /= V_Text then
         return False;
      end if;
      if V.Length /= E.Text_Value.Length then
         return False;
      end if;
      for I in 1 .. V.Length loop
         if To_Lower_Char (V.Data (I))
           /= To_Lower_Char (E.Text_Value.Data (I))
         then
            return False;
         end if;
      end loop;
      return True;
   end Match_Exact;

   function Match_Contains (V : Value_Text; E : Event_Value) return Boolean is
   begin
      if E.Kind /= V_Text then
         return False;
      end if;
      if V.Length = 0 then
         return True;
      end if;
      if E.Text_Value.Length < V.Length then
         return False;
      end if;
      for Start in 1 .. E.Text_Value.Length - V.Length + 1 loop
         declare
            Found : Boolean := True;
         begin
            for J in 1 .. V.Length loop
               if To_Lower_Char (E.Text_Value.Data (Start + J - 1))
                 /= To_Lower_Char (V.Data (J))
               then
                  Found := False;
                  exit;
               end if;
            end loop;
            if Found then
               return True;
            end if;
         end;
      end loop;
      return False;
   end Match_Contains;

   function Match_Startswith (V : Value_Text; E : Event_Value) return Boolean is
   begin
      if E.Kind /= V_Text then
         return False;
      end if;
      if V.Length = 0 then
         return True;
      end if;
      if E.Text_Value.Length < V.Length then
         return False;
      end if;
      for I in 1 .. V.Length loop
         if To_Lower_Char (E.Text_Value.Data (I))
           /= To_Lower_Char (V.Data (I))
         then
            return False;
         end if;
      end loop;
      return True;
   end Match_Startswith;

   function Match_Endswith (V : Value_Text; E : Event_Value) return Boolean is
      Base : Natural;
   begin
      if E.Kind /= V_Text then
         return False;
      end if;
      if V.Length = 0 then
         return True;
      end if;
      if E.Text_Value.Length < V.Length then
         return False;
      end if;
      Base := E.Text_Value.Length - V.Length;
      for I in 1 .. V.Length loop
         if To_Lower_Char (E.Text_Value.Data (Base + I))
           /= To_Lower_Char (V.Data (I))
         then
            return False;
         end if;
      end loop;
      return True;
   end Match_Endswith;

   --  Dispatch on the LAST supported matcher in the chain: Sigma
   --  applies value modifiers left to right, so the final contains /
   --  startswith / endswith decides the comparison; exact equality is
   --  the empty-chain case. Any unsupported element was already
   --  rejected by Chain_Supported before we get here.
   function Match_Field
     (C : Field_Constraint; E : Event_Value) return Boolean
   is
      Last : Modifier_Kind := Mod_None;
   begin
      for I in 1 .. C.Modifiers.Count loop
         if C.Modifiers.Items (I) in
           Mod_Contains | Mod_Startswith | Mod_Endswith
         then
            Last := C.Modifiers.Items (I);
         end if;
      end loop;
      case C.Expected.Kind is
         when E_Text =>
            case Last is
               when Mod_None =>
                  return Match_Exact (C.Expected.Single, E);
               when Mod_Contains =>
                  return Match_Contains (C.Expected.Single, E);
               when Mod_Startswith =>
                  return Match_Startswith (C.Expected.Single, E);
               when Mod_Endswith =>
                  return Match_Endswith (C.Expected.Single, E);
               when others =>
                  return False;
            end case;
         when E_Text_List =>
            for I in 1 .. C.Expected.Count loop
               case Last is
                  when Mod_None =>
                     if Match_Exact (C.Expected.Items (I), E) then
                        return True;
                     end if;
                  when Mod_Contains =>
                     if Match_Contains (C.Expected.Items (I), E) then
                        return True;
                     end if;
                  when Mod_Startswith =>
                     if Match_Startswith (C.Expected.Items (I), E) then
                        return True;
                     end if;
                  when Mod_Endswith =>
                     if Match_Endswith (C.Expected.Items (I), E) then
                        return True;
                     end if;
                  when others =>
                     return False;
               end case;
            end loop;
            return False;
         when E_Int =>
            if E.Kind /= V_Int then
               return False;
            end if;
            return E.Int_Value = C.Expected.Int_Value;
         when E_Int_List =>
            if E.Kind /= V_Int then
               return False;
            end if;
            for I in 1 .. C.Expected.Int_Count loop
               if E.Int_Value = C.Expected.Ints (I) then
                  return True;
               end if;
            end loop;
            return False;
         when E_Pattern =>
            --  `re` / wildcard bodies are opaque until Phase 2.
            return False;
      end case;
   end Match_Field;

   ----------------
   --  Selection --
   ----------------

   function Find_Event_Field
     (Event : Event_Record; Name : Field_Name) return Natural
   is
   begin
      for I in 1 .. Event.Count loop
         if Image_Of (Event.Fields (I).Name)
           = Image_Of (Name)
         then
            return I;
         end if;
      end loop;
      return 0;
   end Find_Event_Field;

   function Eval_Selection
     (Sel : Selection; Event : Event_Record) return Eval_Result
   is
   begin
      for I in 1 .. Sel.Field_Count loop
         declare
            C   : Field_Constraint renames Sel.Fields (I);
            Idx : constant Natural := Find_Event_Field (Event, C.Field);
         begin
            if not Chain_Supported (C.Modifiers) then
               return (Matched => False,
                       Error   => Error_Unsupported_Modifier);
            end if;
            if C.Expected.Kind = E_Pattern then
               return (Matched => False,
                       Error   => Error_Unsupported_Modifier);
            end if;
            if Idx = 0 then
               return (Matched => False, Error => Error_None);
            end if;
            if not Match_Field (C, Event.Fields (Idx).Value) then
               return (Matched => False, Error => Error_None);
            end if;
         end;
      end loop;
      return (Matched => True, Error => Error_None);
   end Eval_Selection;

   ----------------
   --  Condition --
   ----------------

   function Eval_Node
     (Rule  : Compiled_Rule;
      Event : Event_Record;
      Idx   : Positive;
      Fuel  : Natural) return Eval_Result
   with Subprogram_Variant => (Decreases => Fuel)
   is
      N : Condition_Node renames Rule.Nodes (Idx);
   begin
      if Fuel = 0 then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      case N.Kind is
         when N_Ref =>
            if N.Sel_Index < 1 or else N.Sel_Index > Rule.Sel_Count then
               return (Matched => False, Error => Error_Invalid_Rule);
            end if;
            return Eval_Selection (Rule.Selections (N.Sel_Index), Event);
         when N_Not =>
            if N.Child < 1 or else N.Child > Rule.Node_Count then
               return (Matched => False, Error => Error_Invalid_Rule);
            end if;
            declare
               Inner : constant Eval_Result :=
                 Eval_Node (Rule, Event, N.Child, Fuel - 1);
            begin
               if Inner.Error /= Error_None then
                  return Inner;
               end if;
               return (Matched => not Inner.Matched, Error => Error_None);
            end;
         when N_And =>
            if N.Left < 1 or else N.Left > Rule.Node_Count
              or else N.Right < 1 or else N.Right > Rule.Node_Count
            then
               return (Matched => False, Error => Error_Invalid_Rule);
            end if;
            declare
               L : constant Eval_Result :=
                 Eval_Node (Rule, Event, N.Left, Fuel - 1);
               R : constant Eval_Result :=
                 Eval_Node (Rule, Event, N.Right, Fuel - 1);
            begin
               if L.Error /= Error_None then
                  return L;
               end if;
               if R.Error /= Error_None then
                  return R;
               end if;
               return (Matched => L.Matched and R.Matched,
                       Error   => Error_None);
            end;
         when N_Or =>
            if N.Left < 1 or else N.Left > Rule.Node_Count
              or else N.Right < 1 or else N.Right > Rule.Node_Count
            then
               return (Matched => False, Error => Error_Invalid_Rule);
            end if;
            declare
               L : constant Eval_Result :=
                 Eval_Node (Rule, Event, N.Left, Fuel - 1);
               R : constant Eval_Result :=
                 Eval_Node (Rule, Event, N.Right, Fuel - 1);
            begin
               if L.Error /= Error_None then
                  return L;
               end if;
               if R.Error /= Error_None then
                  return R;
               end if;
               return (Matched => L.Matched or R.Matched,
                       Error   => Error_None);
            end;
         when N_One_Of =>
            declare
               Any      : Boolean := False;
               Any_Err  : Eval_Error := Error_None;
               Any_Seen : Boolean := False;
            begin
               for I in 1 .. Rule.Sel_Count loop
                  if Has_Prefix (Rule.Selections (I).Name, N.Prefix) then
                     Any_Seen := True;
                     declare
                        R : constant Eval_Result :=
                          Eval_Selection (Rule.Selections (I), Event);
                     begin
                        if R.Error /= Error_None then
                           Any_Err := R.Error;
                        elsif R.Matched then
                           Any := True;
                        end if;
                     end;
                  end if;
               end loop;
               if Any_Err /= Error_None then
                  return (Matched => False, Error => Any_Err);
               end if;
               if not Any_Seen then
                  return (Matched => False, Error => Error_Invalid_Rule);
               end if;
               return (Matched => Any, Error => Error_None);
            end;
         when N_All_Of =>
            declare
               All      : Boolean := True;
               Any_Err  : Eval_Error := Error_None;
               Any_Seen : Boolean := False;
            begin
               for I in 1 .. Rule.Sel_Count loop
                  if Has_Prefix (Rule.Selections (I).Name, N.Prefix) then
                     Any_Seen := True;
                     declare
                        R : constant Eval_Result :=
                          Eval_Selection (Rule.Selections (I), Event);
                     begin
                        if R.Error /= Error_None then
                           Any_Err := R.Error;
                        elsif not R.Matched then
                           All := False;
                        end if;
                     end;
                  end if;
               end loop;
               if Any_Err /= Error_None then
                  return (Matched => False, Error => Any_Err);
               end if;
               if not Any_Seen then
                  return (Matched => False, Error => Error_Invalid_Rule);
               end if;
               return (Matched => All, Error => Error_None);
            end;
         when N_Near | N_Count =>
            return (Matched => False,
                    Error   => Error_Unsupported_Condition);
      end case;
   end Eval_Node;

   function Empty_Rule return Compiled_Rule is
     ((Selections => [others =>
        (Name        => <>, Fields => [others => <>], Field_Count => 0)],
       Sel_Count  => 0,
       Nodes      => [others => <>],
       Node_Count => 0,
       Root       => 0));

   function Evaluate
     (Rule : Compiled_Rule; Event : Event_Record) return Eval_Result
   is
   begin
      if Rule.Root < 1 or else Rule.Root > Rule.Node_Count then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      return Eval_Node (Rule, Event, Rule.Root, Max_Condition_Nodes);
   end Evaluate;

end Sigma_Verdict.Engine;
