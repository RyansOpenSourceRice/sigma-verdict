with Ada.Text_IO;
with Sigma_Verdict.Boundary;
with Sigma_Verdict.Defaults;

--  Minimal embedding example: load a Sigma rule and test one event.
procedure Detect_Whoami is

   use Sigma_Verdict.Defaults.Engine;
   use Sigma_Verdict.Boundary;

   Rule   : E.Compiled_Rule;
   Error  : Load_Error;
   Detail : Natural;
   Event  : Event_Record;

begin
   Load_Detection
     ("title: demo" & ASCII.LF &
      "detection:" & ASCII.LF &
      "  selection:" & ASCII.LF &
      "    EventID: 4728" & ASCII.LF &
      "    CommandLine|contains: 'whoami'" & ASCII.LF &
      "  condition: selection" & ASCII.LF,
      Rule, Error, Detail);
   if Error /= Load_Ok then
      Ada.Text_IO.Put_Line ("load failed: " & Load_Error'Image (Error));
      return;
   end if;

   Event.Count := 2;
   Event.Fields (1).Name := To_Field_Name ("EventID").Value;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Name := To_Field_Name ("CommandLine").Value;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami").Value);

   Ada.Text_IO.Put_Line
     ("verdict:" & Boolean'Image (Evaluate (Rule, Event).Matched));
end Detect_Whoami;
