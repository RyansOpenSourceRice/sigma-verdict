with Sigma_Verdict.Defaults;

--  Smoke test: EventID 4728 + CommandLine contains "whoami".
procedure Smoke is

   use Sigma_Verdict.Defaults.Engine;

   Rule  : Compiled_Rule := Empty_Rule;
   Event : Event_Record;
   R     : Eval_Result;

   procedure Check (Cond : Boolean; Name : String) is
   begin
      if not Cond then
         raise Program_Error with "FAILED: " & Name;
      end if;
   end Check;

begin
   --  selection:
   --    EventID: 4728
   --    CommandLine|contains: 'whoami'
   Rule.Sel_Count := 1;
   Rule.Selections (1).Name := To_Field_Name ("selection").Value;
   Rule.Selections (1).Field_Count := 2;

   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
      Expected  => (Kind => E_Int, Int_Value => 4728));

   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("whoami").Value));

   Rule.Node_Count := 1;
   Rule.Nodes (1) := (Kind => N_Ref, Sel_Index => 1);
   Rule.Root := 1;

   --  Matching event.
   Event.Count := 2;
   Event.Fields (1).Name := To_Field_Name ("EventID").Value;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Name := To_Field_Name ("CommandLine").Value;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("C:\x whoami /all").Value);

   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "match");

   --  Wrong EventID must not match.
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4738);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "eventid mismatch");

   --  Missing whoami must not match.
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("C:\x hostname").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "text mismatch");
end Smoke;
