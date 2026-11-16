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

   --  Regression: endswith with a needle longer than the haystack must
   --  fail closed (no match, no error), never raise on the offset
   --  subtraction.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Endswith,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("whoami /all plus extra").Value));
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "endswith longer needle");

   --  Sanity: a genuine endswith still matches.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind   => E_Text,
      Single => To_Value_Text ("whoami").Value);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "endswith match");

   --  ---- P1a: cased / all / exists ----

   --  cased: exact case required.
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Cased,
                                          2 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("WHOAMI").Value));
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cased mismatch");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run WHOAMI").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cased match");

   --  all: every list item must match (AND).
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Contains,
                                          2 => Mod_All,
                                          others => Mod_None]),
      Expected  => (Kind  => E_Text_List,
                    Items => [1 => To_Value_Text ("whoami").Value,
                              2 => To_Value_Text ("/priv").Value,
                              others => (Length => 0,
                                         Data   => [others => ' '])],
                    Count => 2));
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami /priv").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "all both present");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami /all").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "all one missing");

   --  exists: presence only, polarity from the value.
   Rule.Selections (1).Field_Count := 1;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Exists,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 1));
   Event.Count := 2;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4738);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "exists present");
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
      Expected  => (Kind => E_Int, Int_Value => 4728));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Exists,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 0));
   Event.Count := 1;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "exists false absent");
   Event.Count := 2;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("x").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "exists false present");

   --  all over integers; field 2 reset to a benign matcher.
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_All,
                                          others => Mod_None]),
      Expected  => (Kind      => E_Int_List,
                    Ints      => [4728, 4738, others => 0],
                    Int_Count => 2));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("whoami").Value));
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "int all missing one");
   Rule.Selections (1).Fields (1).Modifiers := Empty_Modifiers;
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "int any present");

   --  Defence in depth: illegal hand-built chains fail closed.
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
      Expected  => (Kind => E_Int, Int_Value => 4728));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Contains,
                                          2 => Mod_Startswith,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("whoami").Value));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "two matchers unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Exists,
                                          2 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 1));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "exists plus matcher unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Exists,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("maybe").Value));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "exists non-bool unsupported");
end Smoke;
