--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

package body Sigma_Verdict.Engine with SPARK_Mode is

   ------------------
   --  Constructors --
   ------------------

   function To_Field_Name (S : String) return Field_Result is
      R : Field_Result;
   begin
      if S'Length > Max_Field_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Field_Name;

   function To_Value_Text (S : String) return Value_Result is
      R : Value_Result;
   begin
      if S'Length > Max_Value_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Value_Text;

   function To_Event_Text (S : String) return Event_Text_Result is
      R : Event_Text_Result;
   begin
      if S'Length > Max_Event_Value_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Event_Text;

   function To_Pattern (S : String) return Pattern_Result is
      R : Pattern_Result;
   begin
      if S'Length > Max_Pattern_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Pattern;

   function Image_Of (F : Field_Name) return String is
     (F.Data (1 .. F.Length));

   -----------------
   --  Modifiers --
   -----------------

   function Same_Word (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  A (A'First + I) = B (B'First + I)));

   function Parse_Modifier (Token : String) return Modifier_Kind is
   begin
      if Same_Word (Token, "contains") then
         return Mod_Contains;
      elsif Same_Word (Token, "startswith") then
         return Mod_Startswith;
      elsif Same_Word (Token, "endswith") then
         return Mod_Endswith;
      elsif Same_Word (Token, "re") then
         return Mod_Re;
      elsif Same_Word (Token, "re+i") or else Same_Word (Token, "i") then
         return Mod_Re_I;
      elsif Same_Word (Token, "re+m") or else Same_Word (Token, "m") then
         return Mod_Re_M;
      elsif Same_Word (Token, "re+s") or else Same_Word (Token, "s") then
         return Mod_Re_S;
      elsif Same_Word (Token, "windash") then
         return Mod_Windash;
      elsif Same_Word (Token, "wide") then
         return Mod_Wide;
      elsif Same_Word (Token, "utf16le") then
         return Mod_UTF16LE;
      elsif Same_Word (Token, "utf16be") then
         return Mod_UTF16BE;
      elsif Same_Word (Token, "base64") then
         return Mod_Base64;
      elsif Same_Word (Token, "base64offset") then
         return Mod_Base64Offset;
      elsif Same_Word (Token, "cased") then
         return Mod_Cased;
      elsif Same_Word (Token, "all") then
         return Mod_All;
      elsif Same_Word (Token, "exists") then
         return Mod_Exists;
      elsif Same_Word (Token, "fieldref") then
         return Mod_Fieldref;
      elsif Same_Word (Token, "expand") then
         return Mod_Expand;
      elsif Same_Word (Token, "gt") then
         return Mod_GT;
      elsif Same_Word (Token, "gte") then
         return Mod_GTE;
      elsif Same_Word (Token, "lt") then
         return Mod_LT;
      elsif Same_Word (Token, "lte") then
         return Mod_LTE;
      elsif Same_Word (Token, "cidr") then
         return Mod_CIDR;
      else
         return Mod_Unknown;
      end if;
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

   function Has_Modifier
     (Set : Modifier_Set; M : Modifier_Kind) return Boolean
   is
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) = M then
            return True;
         end if;
      end loop;
      return False;
   end Has_Modifier;

   function Chain_Supported (Set : Modifier_Set) return Boolean is
      Seen_Matcher : Boolean := False;
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Is_Supported_Modifier (Set.Items (I)) then
            --  At most one matching semantic per chain; several would
            --  silently shadow each other, so the chain fails closed.
            if Seen_Matcher then
               return False;
            end if;
            Seen_Matcher := True;
         elsif Set.Items (I) not in Mod_Cased | Mod_All | Mod_Exists then
            return False;
         end if;
      end loop;
      return True;
   end Chain_Supported;

   ----------------
   --  Matching --
   ----------------

   function Fold (C : Character; Sensitive : Boolean) return Character is
     (if (not Sensitive) and then C in 'A' .. 'Z'
      then Character'Val (Character'Pos (C) + 32)
      else C);

   function Equal_Folded
     (A, B : String; Sensitive : Boolean) return Boolean
   is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  Fold (A (A'First + I), Sensitive) =
                    Fold (B (B'First + I), Sensitive)));

   function Same_Bytes (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  A (A'First + I) = B (B'First + I)));

   function Field_Equal (A, B : Field_Name) return Boolean is
     (A.Length = B.Length
      and then Same_Bytes (A.Data (1 .. A.Length), B.Data (1 .. B.Length)));

   function Contains_At
     (Haystack, Needle : String; Sensitive : Boolean) return Boolean
   is
      Match : Boolean;
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for Start in 0 .. Haystack'Length - Needle'Length loop
         Match := True;
         for K in 0 .. Needle'Length - 1 loop
            pragma Loop_Invariant (Start <= Haystack'Length - Needle'Length);
            pragma Loop_Invariant (K <= Needle'Length - 1);
            if Fold (Haystack (Haystack'First + Start + K), Sensitive) /=
              Fold (Needle (Needle'First + K), Sensitive)
            then
               Match := False;
               exit;
            end if;
         end loop;
         if Match then
            return True;
         end if;
         pragma Loop_Invariant (Needle'Length <= Haystack'Length);
      end loop;
      return False;
   end Contains_At;

   function Starts_With_At
     (Haystack, Needle : String; Sensitive : Boolean) return Boolean
   is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for K in 0 .. Needle'Length - 1 loop
         pragma Loop_Invariant (Needle'Length <= Haystack'Length);
         if Fold (Haystack (Haystack'First + K), Sensitive) /=
           Fold (Needle (Needle'First + K), Sensitive)
         then
            return False;
         end if;
      end loop;
      return True;
   end Starts_With_At;

   function Ends_With_At
     (Haystack, Needle : String; Sensitive : Boolean) return Boolean
   is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      --  Offset is elaborated only after the guards above, so the
      --  subtraction cannot underflow (fail-closed, no exception).
      declare
         Offset : constant Natural := Haystack'Length - Needle'Length;
      begin
         for K in 0 .. Needle'Length - 1 loop
            pragma Loop_Invariant (Offset = Haystack'Length - Needle'Length);
            pragma Loop_Invariant (Offset + K <= Haystack'Length);
            if Fold (Haystack (Haystack'First + Offset + K), Sensitive) /=
              Fold (Needle (Needle'First + K), Sensitive)
            then
               return False;
            end if;
         end loop;
         return True;
      end;
   end Ends_With_At;

   function Has_Prefix (Name, Prefix : Field_Name) return Boolean is
   begin
      if Prefix.Length = 0 then
         return True;
      end if;
      if Prefix.Length > Name.Length then
         return False;
      end if;
      return Same_Bytes
        (Name.Data (1 .. Prefix.Length), Prefix.Data (1 .. Prefix.Length));
   end Has_Prefix;

   function Find_Field
     (Event : Event_Record; Name : Field_Name) return Natural
   is
   begin
      for I in 1 .. Event.Count loop
         pragma Loop_Invariant (Event.Count <= Max_Event_Fields);
         if Field_Equal (Event.Fields (I).Name, Name) then
            return I;
         end if;
      end loop;
      return 0;
   end Find_Field;

   --  Match one expected text against one haystack under the chain's
   --  single matcher. Chain_Supported guarantees at most one matching
   --  semantic reaches here (empty means exact equality); `cased`
   --  selects case-sensitive comparison, otherwise folding applies.
   function Text_Matches
     (Haystack : String; Needle : String; Set : Modifier_Set) return Boolean
   is
      Kind      : Modifier_Kind := Mod_None;
      Sensitive : constant Boolean := Has_Modifier (Set, Mod_Cased);
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) in Mod_Contains | Mod_Startswith | Mod_Endswith then
            Kind := Set.Items (I);
         end if;
      end loop;
      case Kind is
         when Mod_Contains =>
            return Contains_At (Haystack, Needle, Sensitive);
         when Mod_Startswith =>
            return Starts_With_At (Haystack, Needle, Sensitive);
         when Mod_Endswith =>
            return Ends_With_At (Haystack, Needle, Sensitive);
         when others =>
            return Equal_Folded (Haystack, Needle, Sensitive);
      end case;
   end Text_Matches;

   function Match_Field
     (C : Field_Constraint; Event : Event_Record) return Eval_Result
   is
      Slot : constant Natural := Find_Field (Event, C.Field);
   begin
      --  Presence check. The boundary only ever loads sole-modifier
      --  boolean values here; anything else fails closed as defence
      --  in depth (hand-built rules bypass the loader).
      if Has_Modifier (C.Modifiers, Mod_Exists) then
         if C.Modifiers.Count /= 1 then
            return (Matched => False, Error => Error_Unsupported_Modifier);
         end if;
         case C.Expected.Kind is
            when E_Int =>
               return (Matched => (Slot /= 0) = (C.Expected.Int_Value /= 0),
                       Error   => Error_None);
            when E_Text =>
               declare
                  T : constant String :=
                    C.Expected.Single.Data (1 .. C.Expected.Single.Length);
               begin
                  if Equal_Folded (T, "true", False) then
                     return (Matched => Slot /= 0, Error => Error_None);
                  elsif Equal_Folded (T, "false", False) then
                     return (Matched => Slot = 0, Error => Error_None);
                  else
                     return (Matched => False,
                             Error   => Error_Unsupported_Modifier);
                  end if;
               end;
            when E_Int_List | E_Text_List | E_Pattern =>
               return (Matched => False,
                       Error   => Error_Unsupported_Modifier);
         end case;
      end if;
      if not Chain_Supported (C.Modifiers) then
         return (Matched => False, Error => Error_Unsupported_Modifier);
      end if;
      if C.Expected.Kind = E_Pattern then
         return (Matched => False, Error => Error_Unsupported_Modifier);
      end if;
      if Slot = 0 then
         --  Absent field: no match, no error (standard Sigma semantics).
         return (Matched => False, Error => Error_None);
      end if;
      declare
         EV : constant Event_Value := Event.Fields (Slot).Value;
      begin
         case C.Expected.Kind is
            when E_Int =>
               if EV.Kind = V_Int and then EV.Int_Value = C.Expected.Int_Value then
                  return (Matched => True, Error => Error_None);
               end if;
               return (Matched => False, Error => Error_None);
            when E_Int_List =>
               if EV.Kind /= V_Int then
                  return (Matched => False, Error => Error_None);
               end if;
               if C.Expected.Int_Count = 0 then
                  --  An empty list matches nothing either way.
                  return (Matched => False, Error => Error_None);
               end if;
               if Has_Modifier (C.Modifiers, Mod_All) then
                  for I in 1 .. C.Expected.Int_Count loop
                     pragma Loop_Invariant
                       (C.Expected.Int_Count <= Max_Values_Per_Sel);
                     if EV.Int_Value /= C.Expected.Ints (I) then
                        return (Matched => False, Error => Error_None);
                     end if;
                  end loop;
                  return (Matched => True, Error => Error_None);
               end if;
               for I in 1 .. C.Expected.Int_Count loop
                  pragma Loop_Invariant
                    (C.Expected.Int_Count <= Max_Values_Per_Sel);
                  if EV.Int_Value = C.Expected.Ints (I) then
                     return (Matched => True, Error => Error_None);
                  end if;
               end loop;
               return (Matched => False, Error => Error_None);
            when E_Text =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_None);
               end if;
               if Text_Matches
                 (EV.Text_Value.Data (1 .. EV.Text_Value.Length),
                  C.Expected.Single.Data (1 .. C.Expected.Single.Length),
                  C.Modifiers)
               then
                  return (Matched => True, Error => Error_None);
               end if;
               return (Matched => False, Error => Error_None);
            when E_Text_List =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_None);
               end if;
               if C.Expected.Count = 0 then
                  --  An empty list matches nothing either way.
                  return (Matched => False, Error => Error_None);
               end if;
               if Has_Modifier (C.Modifiers, Mod_All) then
                  for I in 1 .. C.Expected.Count loop
                     pragma Loop_Invariant
                       (C.Expected.Count <= Max_Values_Per_Sel);
                     if not Text_Matches
                       (EV.Text_Value.Data (1 .. EV.Text_Value.Length),
                        C.Expected.Items (I).Data
                          (1 .. C.Expected.Items (I).Length),
                        C.Modifiers)
                     then
                        return (Matched => False, Error => Error_None);
                     end if;
                  end loop;
                  return (Matched => True, Error => Error_None);
               end if;
               for I in 1 .. C.Expected.Count loop
                  pragma Loop_Invariant
                    (C.Expected.Count <= Max_Values_Per_Sel);
                  if Text_Matches
                    (EV.Text_Value.Data (1 .. EV.Text_Value.Length),
                     C.Expected.Items (I).Data
                       (1 .. C.Expected.Items (I).Length),
                     C.Modifiers)
                  then
                     return (Matched => True, Error => Error_None);
                  end if;
               end loop;
               return (Matched => False, Error => Error_None);
            when E_Pattern =>
               return (Matched => False, Error => Error_Unsupported_Modifier);
         end case;
      end;
   end Match_Field;

   function Match_Selection
     (Sel : Selection; Event : Event_Record) return Eval_Result
   is
   begin
      for I in 1 .. Sel.Field_Count loop
         pragma Loop_Invariant (Sel.Field_Count <= Max_Fields_Per_Sel);
         declare
            R : constant Eval_Result := Match_Field (Sel.Fields (I), Event);
         begin
            if R.Error /= Error_None then
               return R;
            end if;
            if not R.Matched then
               return (Matched => False, Error => Error_None);
            end if;
         end;
      end loop;
      --  A selection with zero fields cannot match; the boundary
      --  rejects such rules at load, this is defence in depth.
      if Sel.Field_Count = 0 then
         return (Matched => False, Error => Error_None);
      end if;
      return (Matched => True, Error => Error_None);
   end Match_Selection;

   function Eval_Node
     (Rule : Compiled_Rule; Event : Event_Record; Idx : Positive;
      Fuel : Natural)
      return Eval_Result
   with Subprogram_Variant => (Decreases => Fuel)
   is
   begin
      if Fuel = 0 then
         --  Cyclic node graph: fail closed instead of recursing forever.
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      if Idx > Rule.Node_Count then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      declare
         N : constant Condition_Node := Rule.Nodes (Idx);
      begin
         case N.Kind is
            when N_Ref =>
               if N.Sel_Index > Rule.Sel_Count then
                  return (Matched => False, Error => Error_Invalid_Rule);
               end if;
               return Match_Selection (Rule.Selections (N.Sel_Index), Event);
            when N_Not =>
               declare
                  C : constant Eval_Result := Eval_Node (Rule, Event, N.Child, Fuel - 1);
               begin
                  if C.Error /= Error_None then
                     return C;
                  end if;
                  return (Matched => not C.Matched, Error => Error_None);
               end;
            when N_And =>
               declare
                  L : constant Eval_Result := Eval_Node (Rule, Event, N.Left, Fuel - 1);
                  R : constant Eval_Result := Eval_Node (Rule, Event, N.Right, Fuel - 1);
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
               declare
                  L : constant Eval_Result := Eval_Node (Rule, Event, N.Left, Fuel - 1);
                  R : constant Eval_Result := Eval_Node (Rule, Event, N.Right, Fuel - 1);
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
                  First_Error : Eval_Error := Error_None;
                  Saw_Error   : Boolean := False;
               begin
                  for I in 1 .. Rule.Sel_Count loop
                     pragma Loop_Invariant (Rule.Sel_Count <= Max_Selections);
                     if Has_Prefix (Rule.Selections (I).Name, N.Prefix) then
                        declare
                           R : constant Eval_Result :=
                             Match_Selection (Rule.Selections (I), Event);
                        begin
                           if R.Error /= Error_None and then not Saw_Error then
                              First_Error := R.Error;
                              Saw_Error := True;
                           end if;
                           if R.Error = Error_None and then R.Matched then
                              return (Matched => True, Error => Error_None);
                           end if;
                        end;
                     end if;
                  end loop;
                  if Saw_Error then
                     --  Fail-closed: a matching-shaped branch errored and
                     --  nothing cleanly matched.
                     return (Matched => False, Error => First_Error);
                  end if;
                  return (Matched => False, Error => Error_None);
               end;
            when N_All_Of =>
               declare
                  First_Error : Eval_Error := Error_None;
                  Saw_Error   : Boolean := False;
               begin
                  for I in 1 .. Rule.Sel_Count loop
                     pragma Loop_Invariant (Rule.Sel_Count <= Max_Selections);
                     if Has_Prefix (Rule.Selections (I).Name, N.Prefix) then
                        declare
                           R : constant Eval_Result :=
                             Match_Selection (Rule.Selections (I), Event);
                        begin
                           if R.Error /= Error_None then
                              if not Saw_Error then
                                 First_Error := R.Error;
                                 Saw_Error := True;
                              end if;
                           elsif not R.Matched then
                              return (Matched => False, Error => Error_None);
                           end if;
                        end;
                     end if;
                  end loop;
                  if Saw_Error then
                     return (Matched => False, Error => First_Error);
                  end if;
                  --  Vacuous truth over an empty prefix set, per Sigma.
                  return (Matched => True, Error => Error_None);
               end;
            when N_Near | N_Count =>
               return (Matched => False,
                       Error   => Error_Unsupported_Condition);
         end case;
      end;
   end Eval_Node;

   function Empty_Rule return Compiled_Rule is
      R : Compiled_Rule;
   begin
      R.Sel_Count := 0;
      R.Node_Count := 0;
      R.Root := 0;
      return R;
   end Empty_Rule;

   function Evaluate
     (Rule : Compiled_Rule; Event : Event_Record) return Eval_Result
   is
   begin
      if Rule.Root = 0 or else Rule.Root > Rule.Node_Count then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      return Eval_Node (Rule, Event, Rule.Root, Max_Condition_Nodes);
   end Evaluate;

end Sigma_Verdict.Engine;
