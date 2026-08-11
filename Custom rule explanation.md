# Custom Wazuh Rules — Logic & Impact

This document covers the two custom rules written for this project: what each one does, why it's written the way it is, and what actually changed in the alert output before vs. after adding them.

Rule files live in [`local_rules.xml`](./local_rules.xml). This README is the explanation layer on top of that XML — read them side by side.

---

## Contents

- [Rule 100201 — False Positive Suppression](#rule-100201--false-positive-suppression)
- [Rule 100210 — Encoded PowerShell Detection](#rule-100210--encoded-powershell-detection)
- [Before / After — Alert Behavior](#before--after--alert-behavior)
- [How These Were Tested](#how-these-were-tested)
- [Design Notes](#design-notes)

---

## Rule 100201 — False Positive Suppression

**Purpose:** stop a known-benign artifact from the Atomic Red Team test harness from generating an alert, without touching detection of anything else.

### What was happening without it

Running the atomic test (`T1059.001-15`) leaves behind a file/process artifact called `PScriptPolicyTest` as a side effect of how the test harness itself validates PowerShell execution policy — it has nothing to do with the technique being simulated. Wazuh's default rule set still matched on it, because from the log's perspective it's just another PowerShell-related event. That produced an alert that had nothing to do with the actual attacker behavior being tested, sitting in the queue next to the alert that *did* matter.

### The rule

```xml
<rule id="100201" level="0">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)PScriptPolicyTest</field>
  <description>Suppressed: known benign Atomic Red Team test-harness artifact (PScriptPolicyTest)</description>
  <group>false_positive,powershell,atomic_red_team,</group>
</rule>
```

### How it works, line by line

| Element | What it does |
|---|---|
| `id="100201"` | Custom rule ID. Wazuh reserves `100000–119999` for local rules so they never collide with the built-in rule set. |
| `level="0"` | This is the actual suppression mechanism. Wazuh still evaluates and matches the rule, but level `0` means it does not generate an alert. The event isn't deleted — it can still exist in the raw archive log if archiving is enabled — it just doesn't surface as a security alert. |
| `if_sid` | Scopes this rule to only evaluate against events that already matched the broader parent rule (the general Sysmon/PowerShell process-creation rule). This matters for correctness *and* performance — the rule isn't scanning every single log Wazuh receives, only the subset already classified as PowerShell-related activity. |
| `field name="win.eventdata.commandLine" type="pcre2"` | Runs a regex match against the command-line field of the Windows event. `pcre2` is Wazuh's supported regex engine for field matching. |
| `(?i)PScriptPolicyTest` | Case-insensitive match on the specific artifact string. Deliberately narrow — this pattern does not match generic PowerShell usage, encoded commands, or anything else. It only matches this one known artifact. |
| `group` | Tags used for dashboard filtering and correlation later. Tagging it `false_positive` makes it easy to audit later — anyone reviewing this rule set can immediately see this one exists to suppress noise, not to detect anything. |

### What it does *not* do

It does not suppress PowerShell activity in general, encoded commands, or anything from a different process. If the string `PScriptPolicyTest` shows up in a context this project didn't test, it would still get suppressed — that's a known, accepted narrow blind spot, documented here on purpose rather than discovered later.

---

## Rule 100210 — Encoded PowerShell Detection

**Purpose:** produce a clear, high-confidence alert specifically for encoded/obfuscated PowerShell execution, instead of relying on a generic "PowerShell spawned PowerShell" style default rule.

### What was happening without it

The default rule set (e.g. rule `92027`) detects PowerShell spawning PowerShell, which is a reasonable general heuristic but doesn't specifically call out *encoded* command usage — arguably the more meaningful signal, since encoding is commonly used to break simple string-matching and to make a command line harder to read at a glance. The default alert also didn't care about parent process, which is fine, but it wasn't tuned to flag the specific behavior this project was testing for.

### The rule

```xml
<rule id="100210" level="10">
  <if_group>windows</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc\b|-e\b|-ec\b|-encodedcommand)</field>
  <description>PowerShell executed with an encoded/obfuscated command-line parameter</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
  <group>powershell,execution,attack.t1059_001,</group>
</rule>
```

### How it works, line by line

| Element | What it does |
|---|---|
| `level="10"` | Meaningfully higher severity than a routine informational event, reflecting that encoded PowerShell execution is a stronger indicator than plain PowerShell usage on its own. |
| `if_group="windows"` | Scopes evaluation to Windows-sourced events generally, rather than tying it to one specific parent rule ID. This is what makes it independent of parent process — it isn't conditioned on "PowerShell spawned PowerShell," so it still fires if PowerShell is launched some other way (scheduled task, WMI, a script, etc.). |
| First `field` (`win.eventdata.image`) | Confirms the executing binary is `powershell.exe`. Matched via regex rather than an exact string so it's not thrown off by path formatting differences. |
| Second `field` (`win.eventdata.commandLine`) | Looks for any of the common encoded-command flag variants PowerShell accepts: `-enc`, `-e`, `-ec`, `-encodedcommand`. Word boundaries (`\b`) are used on the short flags specifically so `-e` doesn't accidentally match inside an unrelated longer argument. |
| `mitre` block | Maps the rule directly to `T1059.001` in Wazuh's MITRE ATT&CK integration, so the alert shows up correctly tagged in the dashboard's ATT&CK view rather than as an untagged generic alert. |
| `group` | Same purpose as in rule 100201 — dashboard filtering/correlation, plus the `attack.t1059_001` tag specifically feeds Wazuh's MITRE navigator view. |

### Why two separate `field` conditions instead of one combined regex

Both conditions have to match for the rule to fire — Wazuh requires all `field` elements in a rule to match. Splitting the process check from the command-line check keeps each regex simple and independently readable, rather than writing one dense expression that tries to validate both the binary and the flag in a single pattern.

---

## Before / After — Alert Behavior

| Scenario | Before custom rules | After custom rules |
|---|---|---|
| Atomic test harness runs, generates `PScriptPolicyTest` artifact | Default rule matches it, generates an alert unrelated to the actual technique | Rule `100201` matches first, level is forced to `0`, no alert generated |
| `powershell.exe -EncodedCommand <payload>` executes | Generic "PowerShell spawned PowerShell" alert (rule `92027`), no explicit encoding context, dependent on parent process | Rule `100210` fires specifically on the encoded flag, independent of parent process, tagged to `T1059.001`, severity level 10 |
| Analyst reviewing the alert queue | Two alerts to triage, one of which is noise | One alert, clearly labeled, mapped to ATT&CK, no unrelated noise competing for attention |

The net effect isn't "fewer alerts" for its own sake — it's alerts that match what actually happened. One irrelevant alert was removed, and the alert that does matter got more specific and better labeled.

---

## How These Were Tested

Before restarting the Wazuh manager with the new rules loaded, both were validated using Wazuh's built-in rule tester against sample raw log lines pulled from the actual test run, to confirm:

1. Rule `100201` matched the `PScriptPolicyTest` artifact log and correctly suppressed it (no alert produced).
2. Rule `100210` matched the encoded PowerShell execution log and produced an alert at the expected severity level.
3. Neither rule fired on unrelated, non-matching sample logs (basic false-positive check on the rules themselves).

```bash
sudo /var/ossec/bin/wazuh-logtest
```

`wazuh-logtest` takes a pasted raw log line and shows exactly which rule(s) matched it and at what level, without needing to generate live traffic to test a rule change — useful for catching a bad regex before it's live on the manager.

---

## Design Notes

A few deliberate choices worth calling out, since they're the kind of thing that separates "a rule that happens to work" from "a rule written with intent":

- **Suppression via `level="0"` instead of `<if_matched_sid>` exclusion or dropping the log at the agent.** Keeping the match visible in Wazuh (just not alerting on it) preserves the option to review it later if needed, rather than losing the event entirely at the collection layer.
- **Narrow regex scope on both rules.** Neither rule tries to be a general-purpose catch-all. Rule `100201` only ever matches one specific artifact string. Rule `100210` only matches on the actual encoding flags, not "PowerShell doing anything unusual."
- **MITRE tagging on the detection rule, not the suppression rule.** Only `100210` carries the `T1059.001` mapping, since `100201` isn't a detection — tagging a suppression rule with an ATT&CK technique would be misleading in the dashboard.
- **`if_sid` / `if_group` scoping on both rules**, rather than letting them evaluate against the entire log stream. This keeps the custom rules cheap to evaluate and tied to a clear parent context, which matters more as a rule set grows past two rules.
