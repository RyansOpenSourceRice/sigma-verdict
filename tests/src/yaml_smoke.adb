with Ada.Text_IO;
with Sigma_Verdict.Boundary;
with Sigma_Verdict.Defaults;

--  Loads corpus rules end to end: YAML text -> Compiled_Rule -> verdict.
procedure Yaml_Smoke is

   use Sigma_Verdict.Defaults.Engine;
   use Sigma_Verdict.Boundary;

   Rule  : E.Compiled_Rule;
   Event : Event_Record;
   R     : Eval_Result;

   procedure Check (Cond : Boolean; Name : String) is
   begin
      if not Cond then
         raise Program_Error with "FAILED: " & Name;
      end if;
   end Check;

   procedure Load_File (Path : String) is
      F      : Ada.Text_IO.File_Type;
      Text   : String (1 .. 4096);
      Last   : Natural := 0;
      Error  : Load_Error;
      Detail : Natural;
   begin
      Ada.Text_IO.Open (F, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (F) loop
         declare
            Line : constant String := Ada.Text_IO.Get_Line (F);
         begin
            exit when Last + Line'Length + 1 > Text'Last;
            Text (Last + 1 .. Last + Line'Length) := Line;
            Last := Last + Line'Length;
            Text (Last + 1) := ASCII.LF;
            Last := Last + 1;
         end;
      end loop;
      Ada.Text_IO.Close (F);
      Load_Detection (Text (1 .. Last), Rule, Error, Detail);
      if Error /= Load_Ok then
         Ada.Text_IO.Put_Line ("LOAD FAILED: " & Load_Error'Image (Error) &
                                 " at" & Natural'Image (Detail));
         raise Program_Error with "yaml load failed: " & Path;
      end if;
   end Load_File;

   procedure Set_Event (Id : Integer; Cmd : String; Has_Cmd : Boolean := True) is
   begin
      Event.Count := (if Has_Cmd then 2 else 1);
      Event.Fields (1).Name := To_Field_Name ("EventID").Value;
      Event.Fields (1).Value := (Kind => V_Int, Int_Value => Id);
      if Has_Cmd then
         Event.Fields (2).Name := To_Field_Name ("CommandLine").Value;
         Event.Fields (2).Value :=
           (Kind => V_Text, Text_Value => To_Event_Text (Cmd).Value);
      end if;
   end Set_Event;

begin
   --  contains (existing rule).
   Load_File ("tests/corpus/4728_whoami.yml");
   Ada.Text_IO.Put_Line ("loaded selections:" &
                           Selection_Count'Image (Rule.Sel_Count));
   Set_Event (4728, "whoami /priv");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "whoami match");

   --  exists false: matches only when CommandLine is absent.
   Load_File ("tests/corpus/4728_nocmd.yml");
   Set_Event (4728, "", Has_Cmd => False);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "nocmd absent match");
   Set_Event (4728, "whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "nocmd present no match");

   --  cased contains: exact case required.
   Load_File ("tests/corpus/4728_cased.yml");
   Set_Event (4728, "run WHOAMI");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cased match");
   Set_Event (4728, "run whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cased mismatch");

   --  contains all: every list item must match.
   Load_File ("tests/corpus/4728_all.yml");
   Set_Event (4728, "whoami /priv");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "all both present");
   Set_Event (4728, "whoami /all");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "all one missing");

   Ada.Text_IO.Put_Line ("yaml_smoke: matched as expected");
end Yaml_Smoke;
