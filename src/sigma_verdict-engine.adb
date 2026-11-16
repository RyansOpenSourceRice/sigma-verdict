--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

package body Sigma_Verdict.Engine with SPARK_Mode is

   ----------------
   --  Matching  --
   ----------------

   function To_Lower (C : Character) return Character is
   begin
      if C in 'A' .. 'Z' then
         return Character'Val (Character'Pos (C) + 32);
      end if;
      return C;
   end To_Lower;

   function Equal_Fold
     (A, B : String) return Boolean
   is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if To_Lower (A (A'First + I)) /= To_Lower (B (B'First + I)) then
            return False;
         end if;
      end loop;
      return True;
   end Equal_Fold;

   function Field_Name_Equal
     (Event_Name : String; Rule_Name : String; Rule_Len : Natural)
      return Boolean
   is
   begin
      if Rule_Len > Rule_Name'Length or else Rule_Len /= Event_Name'Length
      then
         return False;
      end if;
      return Equal_Fold
        (Event_Name, Rule_Name (Rule_Name'First .. Rule_Name'First + Rule_Len - 1));
   end Field_Name_Equal;

   function Find_Field
     (Event : Event_Record; Name : String; Name_Len : Natural)
      return Natural
   is
   begin
      for I in 1 .. Event.Count loop
         if Field_Name_Equal
              (Event.Fields (I).Name (1 .. Event.Fields (I).N_Len),
               Name, Name_Len)
         then
            return I;
         end if;
      end loop;
      return 0;
   end Find_Field;

   --  Linear substring scan (ASCII case-insensitive). No regex engine,
   --  hence no backtracking and no ReDoS surface (AdaCore Gem #25).
   function Contains_At
     (Haystack : String; Needle : String) return Boolean
   is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for S in 0 .. Haystack'Length - Needle'Length loop
         declare
            Match : Boolean := True;
         begin
            for K in 0 .. Needle'Length - 1 loop
               if To_Lower (Haystack (Haystack'First + S + K)) /=
                 To_Lower (Needle (Needle'First + K))
               then
                  Match := False;
                  exit;
               end if;
            end loop;
            if Match then
               return True;
            end if;
         end;
      end loop;
      return False;
   end Contains_At;

   function Starts_With_At
     (Haystack : String; Needle : String) return Boolean
   is
   begin
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for K in 0 .. Needle'Length - 1 loop
         if To_Lower (Haystack (Haystack'First + K)) /=
           To_Lower (Needle (Needle'First + K))
         then
            return False;
         end if;
      end loop;
      return True;
   end Starts_With_At;

   function Ends_With_At
     (Haystack : String; Needle : String) return Boolean
   is
      Offset : constant Natural := Haystack'Length - Needle'Length;
   begin
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for K in 0 .. Needle'Length - 1 loop
         if To_Lower (Haystack (Haystack'First + Offset + K)) /=
           To_Lower (Needle (Needle'First + K))
         then
            return False;
         end if;
      end loop;
      return True;
   end Ends_With_At;

   function Match_Value_Text
     (Haystack : Bounded_Text;
      Needle   : Bounded_Text;
      Modifier : Supported_Modifier) return Boolean
   is
      H : constant String :=
        Haystack.Data (Haystack.Data'First ..
                         Haystack.Data'First + Haystack.Length - 1)
        with Ghost;
      N : constant String :=
        Needle.Data (Needle.Data'First ..
                       Needle.Data'First + Needle.Length - 1)
        with Ghost;
   begin
      pragma Assert (Haystack.Length <= Haystack.Max_Len);
      pragma Assert (Needle.Length <= Needle.Max_Len);
      case Modifier is
         when Mod_None =>
            return Haystack.Length = Needle.Length
              and then Equal_Fold
                (Haystack.Data
                   (Haystack.Data'First ..
                      Haystack.Data'First + Haystack.Length - 1),
                 Needle.Data
                   (Needle.Data'First ..
                      Needle.Data'First + Needle.Length - 1));
         when Mod_Contains =>
            return Contains_At
              (Haystack.Data
                 (Haystack.Data'First ..
                    Haystack.Data'First + Haystack.Length - 1),
               Needle.Data
                 (Needle.Data'First ..
                    Needle.Data'First + Needle.Length - 1));
         when Mod_Startswith =>
            return Starts_With_At
              (Haystack.Data
                 (Haystack.Data'First ..
                    Haystack.Data'First + Haystack.Length - 1),
               Needle.Data
                 (Needle.Data'First ..
                    Needle.Data'First + Needle.Length - 1));
         when Mod_Endswith =>
            return Ends_With_At
              (Haystack.Data
                 (Haystack.Data'First ..
                    Haystack.Data'First + Haystack.Length - 1),
               Needle.Data
                 (Needle.Data'First ..
                    Needle.Data'First + Needle.Length - 1));
      end case;
   end Match_Value_Text;

   ------------------
   --  Evaluation  --
   ------------------

   --  Classify the modifier chain of one field constraint.
   --  Returns Error_None plus the single effective matcher, or the
   --  first applicable error. Chains longer than one matcher
   --  (e.g. |windash|contains) are Unsupported: the second operator
   --  would change semantics, so guessing is a silent-loss bug.
   procedure Classify_Modifiers
     (Mods     : Modifier_List;
      Modifier : out Supported_Modifier;
      Error    : out Error_Kind)
   is
      Seen_Matcher : Boolean := False;
   begin
      Modifier := Mod_None;
      Error := Error_None;
      for I in 1 .. Mods.Count loop
         pragma Loop_Invariant (Error = Error_None);
         declare
            M : constant Modifier_Kind := Mods.Items (I);
         begin
            case M is
               when Mod_None =>
                  null;
               when Mod_Contains | Mod_Startswith | Mod_Endswith =>
                  if Seen_Matcher then
                     Error := Error_Unsupported_Modifier;
                     return;
                  end if;
                  Seen_Matcher := True;
                  Modifier := M;
               when others =>
                  Error := Error_Unsupported_Modifier;
                  return;
            end case;
         end;
      end loop;
   end Classify_Modifiers;

   function Eval_Field
     (FC : Field_Constraint; Event : Event_Record) return Eval_Result
   is
      Idx      : constant Natural :=
        Find_Field
          (Event, FC.Field (FC.Field'First ..
                              FC.Field'First + FC.Field_Len - 1),
           FC.Field_Len);
      Modifier : Supported_Modifier;
      M_Error  : Error_Kind;
   begin
      if Idx = 0 or else Idx > Event.Count then
         return (Matched => False, Error => Error_Unknown_Field);
      end if;
      Classify_Modifiers (FC.Modifiers, Modifier, M_Error);
      if M_Error /= Error_None then
         return (Matched => False, Error => M_Error);
      end if;
      declare
         EV : Event_Value renames Event.Fields (Idx).Value;
      begin
         case FC.Expected.Kind is
            when E_Int =>
               if EV.Kind /= V_Int then
                  return (Matched => False, Error => Error_Type_Mismatch);
               end if;
               --  Integer equality is modifier-free; any matcher here
               --  would reinterpret the value, so reject it.
               if Modifier /= Mod_None then
                  return (Matched => False,
                          Error    => Error_Unsupported_Modifier);
               end if;
               return (Matched => EV.Int_Value = FC.Expected.Int_Value,
                       Error   => Error_None);
            when E_Text =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_Type_Mismatch);
               end if;
               return (Matched => Match_Value_Text
                         (EV.Text_Value, FC.Expected.Single, Modifier),
                       Error => Error_None);
            when E_Text_List =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_Type_Mismatch);
               end if;
               for I in 1 .. FC.Expected.List.Count loop
                  if Match_Value_Text
                    (EV.Text_Value, FC.Expected.List.Items (I), Modifier)
                  then
                     return (Matched => True, Error => Error_None);
                  end if;
               end loop;
               return (Matched => False, Error => Error_None);
         end case;
      end;
   end Eval_Field;

   function Eval_Selection
     (Sel : Selection; Event : Event_Record) return Eval_Result
   is
   begin
      if Sel.Field_Count = 0 or else Sel.Field_Count > Max_Fields_Per_Sel
      then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      for I in 1 .. Sel.Field_Count loop
         declare
            R : constant Eval_Result :=
              Eval_Field (Sel.Fields (I), Event);
         begin
            if R.Error /= Error_None then
               return R;
            end if;
            if not R.Matched then
               return (Matched => False, Error => Error_None);
            end if;
         end;
      end loop;
      return (Matched => True, Error => Error_None);
   end Eval_Selection;

   --  Recursive node evaluator. Fuel decreases on every descent, so a
   --  cyclic node graph ends in Error_Invalid_Rule instead of
   --  overflowing the call stack.
   function Eval_Node
     (Rule : Compiled_Rule; Event : Event_Record;
      Idx  : Positive; Fuel : Natural) return Eval_Result
   is
      N : Condition_Node renames Rule.Nodes (Idx);
   begin
      if Fuel = 0 then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      case N.Kind is
         when N_Ref =>
            if N.Sel_Index = 0 or else N.Sel_Index > Rule.Sel_Count then
               return (Matched => False, Error => Error_Invalid_Rule);
            end if;
            return Eval_Selection (Rule.Selections (N.Sel_Index), Event);
         when N_And =>
            if N.Left = 0 or else N.Left > Rule.Node_Count
              or else N.Right = 0 or else N.Right > Rule.Node_Count
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
               return (Matched => L.Matched and then R.Matched,
                       Error   => Error_None);
            end;
         when N_Or =>
            if N.Left = 0 or else N.Left > Rule.Node_Count
              or else N.Right = 0 or else N.Right > Rule.Node_Count
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
               return (Matched => L.Matched or else R.Matched,
                       Error   => Error_None);
            end;
         when N_Not =>
            if N.Left = 0 or else N.Left > Rule.Node_Count then
               return (Matched => False, Error => Error_Invalid_Rule);
            end if;
            declare
               L : constant Eval_Result :=
                 Eval_Node (Rule, Event, N.Left, Fuel - 1);
            begin
               if L.Error /= Error_None then
                  return L;
               end if;
               return (Matched => not L.Matched, Error => Error_None);
            end;
         when N_One_Of | N_All_Of =>
            if N.Left = 0 or else N.Right = 0
              or else N.Left > N.Right
              or else N.Right > Rule.Node_Count
            then
               return (Matched => False,
                       Error   => Error_Unsupported_Condition);
            end if;
            for I in N.Left .. N.Right loop
               pragma Loop_Invariant (I >= N.Left);
               declare
                  R : constant Eval_Result :=
                    Eval_Node (Rule, Event, I, Fuel - 1);
               begin
                  if R.Error /= Error_None then
                     return R;
                  end if;
                  if N.Kind = N_One_Of and then R.Matched then
                     return (Matched => True, Error => Error_None);
                  end if;
                  if N.Kind = N_All_Of and then not R.Matched then
                     return (Matched => False, Error => Error_None);
                  end if;
               end;
            end loop;
            return (Matched => N.Kind = N_All_Of, Error => Error_None);
      end case;
   end Eval_Node;

   function Evaluate
     (Rule : Compiled_Rule; Event : Event_Record) return Eval_Result
   is
   begin
      if Rule.Root = 0 or else Rule.Root > Rule.Node_Count
        or else Rule.Sel_Count = 0
        or else Rule.Sel_Count > Max_Selections
      then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      return Eval_Node (Rule, Event, Rule.Root, Max_Condition_Nodes);
   end Evaluate;

end Sigma_Verdict.Engine;
