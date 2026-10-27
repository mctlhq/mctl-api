# Support agent contract fixtures

These files are synthetic and anonymised. They follow the response shape of the
tenant support agent 0.2.1 exactly (field names, proto-JSON enum strings, part
order, `SupportResult` keys and value types) but hold only placeholder values.

Shape source: mctlhq/mctl-support commit 1784f71 (the executor's completion
event and `agent/result.py` `SupportResult`) and the a2a-sdk 1.2.3 proto.

Never add a recorded response from a real tenant here: this repository is
public. Use the placeholders `example-tenant`, `example-app`, ids of the form
`00000000-0000-4000-8000-0000000000NN` and evidence sources `tool:call_example_N`.
