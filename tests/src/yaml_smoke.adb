with Ada.Text_IO;
with Sigma_Verdict.Boundary;
with Sigma_Verdict.Defaults;

--  Loads tests/corpus/4728_whoami.yml and evaluates one matching event.
procedure Yaml_Smoke is

   use Sigma_Verdict.Defaults.Engine;
   use Sigma_Verdict.Boundary;

   F      : Ada.Text_IO.File_Type;
   Text   : String (1 .. 4096);
   Last   : Natural;
   Rule   : E.Compiled_Rule;
   Error  : Load_Error;
   Detail : Natural;
   Event  : Event_Record;
   R      : Eval_Result;

begin
   Ada.Text_IO.Open (F, Ada.Text_IO.In_File, "tests/corpus/4728_whoami.yml");
   Last := 0;
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
      raise Program_Error with "yaml load failed";
   end if;
   Ada.Text_IO.Put_Line ("loaded selections:" &
                           Selection_Count'Image (Rule.Sel_Count));

   Event.Count := 2;
   Event.Fields (1).Name := To_Field_Name ("EventID").Value;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Name := To_Field_Name ("CommandLine").Value;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami /priv").Value);

   R := Evaluate (Rule, Event);
   if R.Error /= Error_None or else not R.Matched then
      raise Program_Error with "yaml rule did not match";
   end if;
   Ada.Text_IO.Put_Line ("yaml_smoke: matched as expected");
end Yaml_Smoke;
