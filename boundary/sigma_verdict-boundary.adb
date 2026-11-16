--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Event-driven YAML loader on top of adayaml ~0.2.0.
--
--  Accepts the Phase-1 rule shape:
--    detection:
--      <selection-name>:
--        EventID: 4728
--        CommandLine|contains: 'whoami'
--      condition: <selection-name>
--  Metadata keys (title/id/logsource/...) are accepted and ignored.
--  Anything else is an explicit Load_Error.

with Ada.Strings.Fixed;
with Yaml.Parser;
with Yaml.Events;
with Sigma_Verdict.Defaults;

package body Sigma_Verdict.Boundary with SPARK_Mode => Off is

   package EV renames Yaml.Events;

   function Strip_Quotes (S : String) return String is
     (if S'Length >= 2
        and then ((S (S'First) = ''' and then S (S'Last) = ''')
                  or else (S (S'First) = '"' and then S (S'Last) = '"'))
      then S (S'First + 1 .. S'Last - 1)
      else S);

   function To_Lower_Str (S : String) return String is
      R : String (S'Range) := S;
   begin
      for I in R'Range loop
         if R (I) in 'A' .. 'Z' then
            R (I) := Character'Val (Character'Pos (R (I)) + 32);
         end if;
      end loop;
      return R;
   end To_Lower_Str;

   function Split_Modifier (Name : String; Base : out Natural; Has_Mod : out Boolean) return E.Modifier_Kind is
      Bar : constant Natural := Ada.Strings.Fixed.Index (Name, "|");
   begin
      Has_Mod := Bar > 0;
      if Bar = 0 then
         Base := Name'Length;
         return E.Mod_None;
      end if;
      Base := Bar - Name'First;
      declare
         M : constant String := To_Lower_Str (Name (Bar + 1 .. Name'Last));
      begin
         if M = "contains" then
            return E.Mod_Contains;
         elsif M = "startswith" then
            return E.Mod_Startswith;
         elsif M = "endswith" then
            return E.Mod_Endswith;
         else
            return E.Mod_Re;  --  any other modifier: Phase 2 bucket
         end if;
      end;
   end Split_Modifier;

   procedure Set_Field_Name
     (Rule : in out E.Compiled_Rule; Sel : Positive;
      Name : String; Ok : out Boolean)
   is
   begin
      Ok := Name'Length <= Rule.Selections (Sel).Name'Length;
      if Ok then
         Rule.Selections (Sel).Name (1 .. Name'Length) := Name;
         Rule.Selections (Sel).Name_Len := Name'Length;
      end if;
   end Set_Field_Name;

   procedure Add_Field
     (Rule     : in out E.Compiled_Rule;
      Sel      : Positive;
      Name     : String;
      Modifier : E.Modifier_Kind;
      Value    : String;
      Is_Int   : Boolean;
      Int_Val  : Integer;
      Error    : out Load_Error)
   is
      F : E.Field_Constraint renames Rule.Selections (Sel).Fields
        (Rule.Selections (Sel).Field_Count + 1);
   begin
      Error := Load_Ok;
      if Rule.Selections (Sel).Field_Count >= E.Max_Fields_Per_Sel then
         Error := Load_Too_Complex;
         return;
      end if;
      if Name'Length > F.Field'Length then
         Error := Load_Overflow;
         return;
      end if;
      case Modifier is
         when E.Mod_None | E.Mod_Contains | E.Mod_Startswith | E.Mod_Endswith =>
            null;
         when others =>
            Error := Load_Unsupported;
            return;
      end case;
      if Is_Int then
         if Modifier /= E.Mod_None then
            Error := Load_Unsupported;
            return;
         end if;
         if Value'Length > 0 then
            Error := Load_Syntax;
            return;
         end if;
      else
         if Strip_Quotes (Value)'Length > F.Expected.Single.Data'Length then
            Error := Load_Overflow;
            return;
         end if;
      end if;
      Rule.Selections (Sel).Field_Count :=
        Rule.Selections (Sel).Field_Count + 1;
      F.Field (1 .. Name'Length) := Name;
      F.Field_Len := Name'Length;
      F.Modifiers :=
        (Count => (if Modifier = E.Mod_None then 0 else 1),
         Items => [1 => Modifier, others => E.Mod_None]);
      if Is_Int then
         F.Expected :=
           (Max_Len   => F.Expected.Single.Max_Len,
            Max_Items => F.Expected.List.Max_Items,
            Kind      => E.E_Int,
            Int_Value => Int_Val);
      else
         declare
            V : constant String := Strip_Quotes (Value);
         begin
            F.Expected :=
              (Max_Len   => F.Expected.Single.Max_Len,
               Max_Items => F.Expected.List.Max_Items,
               Kind      => E.E_Text,
               Single    =>
                 (Max_Len => F.Expected.Single.Max_Len,
                  Data    => [others => ' '],
                  Length  => V'Length));
            F.Expected.Single.Data (1 .. V'Length) := V;
         end;
      end if;
   end Add_Field;

   type Ctx_State is (C_Root, C_Detection, C_Selection, C_Condition, C_Skip);

   procedure Load_Detection
     (YAML_Text : String;
      Rule      : out E.Compiled_Rule;
      Error     : out Load_Error;
      Detail    : out Natural)
   is
      P           : Yaml.Parser.Instance;
      Ev          : EV.Event;
      State       : Ctx_State := C_Root;
      Skip_Depth  : Natural := 0;
      Sel_Index   : Natural := 0;
      Sel_Count   : Natural := 0;
      Expects_Key : Boolean := True;
      Pending_Key : String (1 .. 256) := [others => ' '];
      Pending_Len : Natural := 0;
      Cond_Text   : String (1 .. 256) := [others => ' '];
      Cond_Len    : Natural := 0;
      In_Cond     : Boolean := False;
      Seen_Detect : Boolean := False;
      Ev_Index    : Natural := 0;

      procedure Fail (E : Load_Error) is
      begin
         Error := E;
         Detail := Ev_Index;
      end Fail;

      function Scalar (E : EV.Event) return String is
        (E.Content.Value.Data.all);

   begin
      Rule := E.Empty_Rule;
      Error := Load_Ok;
      Detail := 0;
      if YAML_Text'Length = 0 then
         Error := Load_Empty_Input;
         return;
      end if;

      P.Set_Input (YAML_Text);
      Main : loop
         begin
            P.Next (Ev);
         exception
            when Yaml.Lexer_Error | Yaml.Parser_Error =>
               Fail (Load_Syntax);
               return;
         end;
         Ev_Index := Ev_Index + 1;
         case Ev.Kind is
            when EV.Stream_Start | EV.Document_Start | EV.Document_End | EV.Stream_End =>
               null;
            when EV.Mapping_Start =>
               if Skip_Depth > 0 then
                  Skip_Depth := Skip_Depth + 1;
               elsif State = C_Root and then Pending_Len > 0
                 and then Pending_Key (1 .. Pending_Len) = "detection"
               then
                  State := C_Detection;
                  Seen_Detect := True;
                  Pending_Len := 0;
               elsif State = C_Detection and then Pending_Len > 0 then
                  if Sel_Count >= E.Max_Selections then
                     Fail (Load_Too_Complex);
                     return;
                  end if;
                  Sel_Count := Sel_Count + 1;
                  Sel_Index := Sel_Count;
                  Rule.Sel_Count := Sel_Count;
                  declare
                     Ok : Boolean;
                  begin
                     Set_Field_Name
                       (Rule, Sel_Index,
                        Pending_Key (1 .. Pending_Len), Ok);
                     if not Ok then
                        Fail (Load_Overflow);
                        return;
                     end if;
                  end;
                  State := C_Selection;
                  Pending_Len := 0;
               elsif State = C_Selection and then Pending_Len > 0 then
                  --  Nested map under a field (e.g. EventID: {...}):
                  --  out of Phase-1 shape.
                  Fail (Load_Unknown_Shape);
                  return;
               elsif State = C_Detection and then Pending_Len = 0 then
                  --  Anonymous map directly under detection: out of shape.
                  Fail (Load_Unknown_Shape);
                  return;
               else
                  --  Document-root mapping or metadata map: skip contents.
                  if State = C_Root and then Pending_Len = 0 then
                     null;
                  else
                     Skip_Depth := 1;
                  end if;
               end if;
               Expects_Key := True;
            when EV.Mapping_End =>
               if Skip_Depth > 0 then
                  Skip_Depth := Skip_Depth - 1;
               elsif State = C_Selection then
                  State := C_Detection;
                  Sel_Index := 0;
               elsif State = C_Detection then
                  State := C_Root;
               end if;
               Expects_Key := True;
            when EV.Sequence_Start =>
               if Skip_Depth > 0 then
                  Skip_Depth := Skip_Depth + 1;
               elsif State = C_Selection and then Pending_Len > 0 then
                  --  List value under a field: Phase 2 (E_Text_List).
                  Fail (Load_Unsupported);
                  return;
               elsif State = C_Detection and then Pending_Len > 0
                 and then Pending_Key (1 .. Pending_Len) = "condition"
               then
                  Fail (Load_Unknown_Condition);
                  return;
               elsif State = C_Detection or else State = C_Selection then
                  Fail (Load_Unknown_Shape);
                  return;
               else
                  Skip_Depth := 1;
               end if;
               Expects_Key := True;
            when EV.Sequence_End =>
               if Skip_Depth > 0 then
                  Skip_Depth := Skip_Depth - 1;
               end if;
               Expects_Key := True;
            when EV.Scalar =>
               if Skip_Depth > 0 then
                  null;
               elsif Expects_Key then
                  if Scalar (Ev)'Length > Pending_Key'Length then
                     Fail (Load_Overflow);
                     return;
                  end if;
                  Pending_Len := Scalar (Ev)'Length;
                  Pending_Key (1 .. Pending_Len) := Scalar (Ev);
                  Expects_Key := False;
                  if State = C_Detection
                    and then Pending_Len = 9
                    and then Pending_Key (1 .. 9) = "condition"
                  then
                     In_Cond := True;
                  end if;
               else
                  --  Scalar value for Pending_Key.
                  if In_Cond then
                     if Scalar (Ev)'Length > Cond_Text'Length then
                        Fail (Load_Overflow);
                        return;
                     end if;
                     Cond_Len := Scalar (Ev)'Length;
                     Cond_Text (1 .. Cond_Len) := Scalar (Ev);
                     In_Cond := False;
                     Pending_Len := 0;
                  elsif State = C_Selection and then Sel_Index > 0 then
                     declare
                        Raw      : constant String := Scalar (Ev);
                        Has_Mod  : Boolean;
                        Base_Len : Natural;
                        Mod      : constant E.Modifier_Kind :=
                          Split_Modifier
                            (Pending_Key (1 .. Pending_Len), Base_Len, Has_Mod);
                        Base     : constant String :=
                          Pending_Key (1 .. Base_Len);
                        Num      : Integer;
                        Is_Num   : Boolean := Raw'Length > 0;
                     begin
                        for C of Raw loop
                           if C not in '0' .. '9' then
                              Is_Num := False;
                              exit;
                           end if;
                        end loop;
                        if Is_Num then
                           begin
                              Num := Integer'Value (Raw);
                           exception
                              when Constraint_Error =>
                                 Fail (Load_Overflow);
                                 return;
                           end;
                        end if;
                        Add_Field
                          (Rule, Sel_Index, Base, Mod, Raw,
                           Is_Num, Num, Error);
                        if Error /= Load_Ok then
                           Fail (Error);
                           return;
                        end if;
                     end;
                     Pending_Len := 0;
                  elsif State = C_Root or else State = C_Detection then
                     --  Metadata scalar (title/logsource/...): ignore.
                     Pending_Len := 0;
                  else
                     Pending_Len := 0;
                  end if;
                  Expects_Key := True;
               end if;
            when EV.Alias =>
               Fail (Load_Unsupported);
               return;
         end case;
         exit Main when Ev.Kind = EV.Stream_End;
      end loop Main;

      if not Seen_Detect then
         Fail (Load_Unknown_Shape);
         return;
      end if;
      if Cond_Len = 0 then
         Fail (Load_Unknown_Condition);
         return;
      end if;
      --  Resolve the condition: a single selection name for Phase 1.
      Sel_Index := 0;
      for I in 1 .. Sel_Count loop
         if Rule.Selections (I).Name_Len = Cond_Len
           and then Rule.Selections (I).Name (1 .. Cond_Len) =
             Cond_Text (1 .. Cond_Len)
         then
            Sel_Index := I;
            exit;
         end if;
      end loop;
      if Sel_Index = 0 then
         Fail (Load_Unknown_Condition);
         return;
      end if;
      if Rule.Node_Count + 1 > E.Max_Condition_Nodes then
         Fail (Load_Too_Complex);
         return;
      end if;
      Rule.Node_Count := Rule.Node_Count + 1;
      Rule.Nodes (Rule.Node_Count) :=
        (Kind => E.N_Ref, Left => 0, Right => 0, Sel_Index => Sel_Index);
      Rule.Root := Rule.Node_Count;
      Error := Load_Ok;
      Detail := 0;
   end Load_Detection;

end Sigma_Verdict.Boundary;
