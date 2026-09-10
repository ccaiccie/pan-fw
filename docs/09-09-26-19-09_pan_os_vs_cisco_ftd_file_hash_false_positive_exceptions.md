# PAN-OS vs Cisco Secure Firewall/FTD: File-Hash False-Positive Exceptions

## Why Cisco FTD Can Whitelist an Exact SHA-256 but PAN-OS Traditional Antivirus and File Blocking Cannot

> Scope: PAN-OS firewalls and Panorama. Cisco Secure Firewall/FTD is discussed only as a comparison point for exact-file malware exception behavior.

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Core Difference](#2-the-core-difference)
3. [How PAN-OS Traditional Antivirus Exceptions Work](#3-how-pan-os-traditional-antivirus-exceptions-work)
4. [Why a PAN-OS Antivirus Exception Is Broader Than a Hash Allowlist](#4-why-a-pan-os-antivirus-exception-is-broader-than-a-hash-allowlist)
5. [Can File Blocking Be Used to Make the Exception?](#5-can-file-blocking-be-used-to-make-the-exception)
6. [How File Blocking and Antivirus Interact](#6-how-file-blocking-and-antivirus-interact)
7. [Can a Separate Security Policy Rule Help?](#7-can-a-separate-security-policy-rule-help)
8. [WildFire Inline ML Is Different](#8-wildfire-inline-ml-is-different)
9. [How Cisco Secure Firewall/FTD Handles Exact SHA-256 Overrides](#9-how-cisco-secure-firewallftd-handles-exact-sha-256-overrides)
10. [Side-by-Side Comparison](#10-side-by-side-comparison)
11. [False Positive vs Signature Collision](#11-false-positive-vs-signature-collision)
12. [Recommended PAN-OS Operational Workflow](#12-recommended-pan-os-operational-workflow)
13. [Panorama Considerations](#13-panorama-considerations)
14. [Verification and Troubleshooting](#14-verification-and-troubleshooting)
15. [Common Mistakes](#15-common-mistakes)
16. [Design and Risk Implications](#16-design-and-risk-implications)
17. [Practical Example](#17-practical-example)
18. [Key Takeaways](#18-key-takeaways)
19. [References](#19-references)

---

## 1. Executive Summary

A common operational requirement is:

> "This exact file is known-good. Its SHA-256 is trusted. Allow this one file, but continue blocking every other file that matches the malware detection."

Cisco Secure Firewall/FTD supports this model directly in its malware/file-policy workflow by allowing an administrator to place the exact full SHA-256 on a **Clean List**.

Traditional PAN-OS Antivirus handling is different. Palo Alto Networks documents **Signature Exceptions** for conventional Antivirus detections. These exceptions are configured using the **Threat ID** associated with the antivirus signature. The exception therefore applies to the signature, not only to one SHA-256.

PAN-OS **File Blocking does not provide a workaround for this limitation**. File Blocking matches file-policy characteristics such as application, file type, transfer direction, and action. It does not provide a SHA-256 match condition that can override a traditional Antivirus detection. Allowing an executable in File Blocking does not tell the Antivirus profile to ignore a matching Threat ID.

PAN-OS does have a file-hash exception capability under **WildFire Inline ML File Exceptions**, but Palo Alto documents that as a separate mechanism for Inline ML enforcement. It must not be confused with a general per-SHA-256 allowlist for traditional Antivirus signatures.

![PAN-OS versus Cisco FTD file-hash exception behavior](../images/09-09-26-19-09_pan_vs_ftd_file_hash_exception.svg)

[Editable draw.io](../images/09-09-26-19-09_pan_vs_ftd_file_hash_exception.drawio)

---

## 2. The Core Difference

### PAN-OS traditional Antivirus

**Source information:** Palo Alto Networks documents that Antivirus signature exceptions are configured using a **Threat ID**. For PAN-OS and Panorama, the administrator opens an Antivirus profile, selects **Signature Exceptions**, and adds the Threat ID to exclude that antivirus signature from enforcement.

Conceptually:

```text
Known-good-file.exe
SHA-256 = H1
       |
       v
Traditional PAN-OS Antivirus engine
       |
       v
Threat ID T123 matched
       |
       v
Signature Exception for T123
       |
       +--> T123 no longer enforced in that Antivirus profile
```

PAN-OS traditional Antivirus does not provide this general rule form:

```text
IF SHA256 == H1
THEN bypass AV signature T123
ELSE continue normal AV enforcement
```

### Cisco Secure Firewall/FTD

Cisco documents a different model in its malware/file-policy framework. A file whose cloud disposition is considered incorrect can have its **full SHA-256** added to a **Clean List**.

Conceptually:

```text
SHA-256 H1 -> Clean List -> treat H1 as clean
SHA-256 H2 -> not on Clean List -> normal malware evaluation
SHA-256 H3 -> not on Clean List -> normal malware evaluation
```

This gives Cisco FTD a more granular exception mechanism for this particular use case.

---

## 3. How PAN-OS Traditional Antivirus Exceptions Work

Palo Alto Networks documents the PAN-OS/Panorama path as:

```text
Objects
  > Security Profiles
    > Antivirus
      > <profile>
        > Signature Exceptions
```

The administrator adds the **Threat ID** associated with the antivirus detection.

The Threat ID can be obtained from the firewall Threat log and investigated using Threat Vault and related threat information.

### Enforcement scope

The practical scope is the Antivirus profile containing the exception and every Security policy rule that references that profile, either directly or through a Security Profile Group.

### Important limitation

The exception key is the **Threat ID**, not the exact SHA-256 of the benign file.

That means the administrator is suppressing enforcement of the identified antivirus signature within the scope of that Antivirus profile rather than making a cryptographic identity exception for only one file.

---

## 4. Why a PAN-OS Antivirus Exception Is Broader Than a Hash Allowlist

Traditional antivirus detection can be signature or pattern based. More than one file can potentially match the same signature.

```text
Malware-A.exe -----------+
                         |
Benign-Software.exe -----+--> both match Threat ID T123
                         |
Another-Sample.exe ------+
```

If the administrator creates an Antivirus Signature Exception for `T123`, PAN-OS is no longer enforcing that antivirus signature in the applicable profile.

This is materially different from exempting only:

```text
SHA-256 = 8af3...9d72
```

### Additional explanation

A SHA-256 allowlist has very narrow identity scope. Changing the file changes the hash. A signature exception can have wider detection scope because the exception suppresses the detection logic identified by the Threat ID.

### Reasonable inference

Because of this difference, a PAN-OS traditional Antivirus exception can have a larger security blast radius than an exact-file hash allowlist. The actual exposure depends on the signature, the policy scope, and whether other security controls detect the same malicious content.

---

## 5. Can File Blocking Be Used to Make the Exception?

**No. A PAN-OS File Blocking profile cannot create an exact-file SHA-256 exception for a traditional Antivirus signature.**

Palo Alto Networks documents File Blocking as a Security Profile used to control file transfers based on file-policy characteristics such as:

```text
Name
Applications
File Types
Direction
Action
```

Typical actions include:

- `alert`
- `block`
- `continue` where supported

A File Blocking rule can express policies such as:

```text
Block PE downloads from general web browsing
Alert on PDF transfers
Allow a particular file type for a particular application
Prompt a user before downloading selected file types
```

It is not documented as accepting a full SHA-256 as a match criterion for bypassing a conventional Antivirus signature.

Therefore this logic is not available through File Blocking:

```text
IF SHA256 == known_good_hash
    bypass traditional AV signature T123
ELSE
    enforce AV normally
```

### Why changing File Blocking does not solve the AV false positive

If File Blocking is configured not to block an executable, that means only that the **File Blocking profile** is not blocking that file type. It does not create an exception in the **Antivirus profile**.

In other words:

```text
File Blocking says: "this file type may pass my control"

Antivirus can still say: "this content matches Threat ID T123"
```

The two controls are independent Security Profiles applied to traffic allowed by Security Policy.

---

## 6. How File Blocking and Antivirus Interact

A Security rule can attach multiple Security Profiles simultaneously:

```text
Security Policy rule
  action: allow
  profiles:
    Antivirus: AV-Strict
    Anti-Spyware: AS-Strict
    Vulnerability Protection: VP-Strict
    URL Filtering: URL-Strict
    File Blocking: FB-Standard
    WildFire Analysis: WF-Forward
```

Allowing content through one profile does not instruct another profile to bypass inspection.

A useful mental model is:

```text
Security Policy allows the session
             |
             v
Application/content becomes identifiable
             |
             +---------------------------+
             |                           |
             v                           v
      File Blocking                 Antivirus
  file type/application/        malware signature/
  direction/action logic        Threat-ID inspection
             |                           |
             +-------------+-------------+
                           |
                           v
                   final enforcement
```

![PAN-OS File Blocking and Antivirus are independent inspection controls](../images/09-09-26-19-09_file_blocking_vs_antivirus_exception.svg)

[Editable draw.io](../images/09-09-26-19-09_file_blocking_vs_antivirus_exception.drawio)

### Example packet/content flow

Consider a user downloading a known-good executable that collides with AV signature `T123`:

```text
Client 10.10.10.25
    |
    | HTTPS download
    v
PAN-OS firewall
    |
    | Security Policy match = allow
    v
Decryption when applicable/configured
    |
    v
App-ID / content decoding
    |
    +--> File Blocking profile
    |      file type = PE
    |      action = alert / non-blocking behavior
    |
    +--> Antivirus profile
           content matches Threat ID T123
           enforcement still occurs
```

The important point is:

```text
File Blocking permits file type
            !=
Skip Antivirus inspection
```

No NAT-specific transformation is relevant to this exception mechanism. The issue is content inspection inside an allowed session.

---

## 7. Can a Separate Security Policy Rule Help?

**Yes, but only as scope reduction. It still cannot match the file hash.**

A separate Security Policy rule can match a narrower business context and attach a dedicated Antivirus profile containing the Threat-ID exception.

Example:

```text
Rule: Approved-Software-Download
Source: Approved-Admin-Users
Destination: Approved-Vendor-Site
Application: ssl, web-browsing, vendor-app as appropriate
Service: application-default
Action: allow
Profiles:
  Antivirus: AV-T123-Temporary-Exception
  File Blocking: FB-Approved-Software
```

Every other rule can continue using the normal strict Antivirus profile.

### What this accomplishes

Instead of disabling `T123` for a broadly shared Antivirus profile, the administrator constrains exposure to a narrow combination of:

```text
source
user
zone
destination
application
service
URL category / destination strategy where appropriate
```

### What it does not accomplish

A standard PAN-OS Security rule cannot express:

```text
SHA256 == abcdef...
```

If a malicious file that also matches `T123` traverses the narrowly scoped exception rule, the Threat-ID exception can apply there too.

Therefore a separate rule is a **blast-radius reduction technique**, not an exact-file allowlist.

---

## 8. WildFire Inline ML Is Different

PAN-OS **does** support File Exceptions using hash information under WildFire Inline Machine Learning.

Typical GUI location:

```text
Objects
  > Security Profiles
    > Antivirus
      > <profile>
        > WildFire Inline ML
          > File Exceptions
```

Palo Alto documentation describes adding hash/partial-hash information together with file metadata such as filename and description for files that should be excluded from WildFire Inline ML enforcement.

This is a key distinction:

| Detection path | PAN-OS exception mechanism |
|---|---|
| Traditional Antivirus signature | Threat-ID / Signature Exception |
| File Blocking | No per-hash AV override |
| WildFire Inline ML | File Exception using hash/partial-hash information |

Do not assume that WildFire Inline ML File Exceptions provide a generic exact-SHA-256 whitelist for every traditional Antivirus event.

---

## 9. How Cisco Secure Firewall/FTD Handles Exact SHA-256 Overrides

Cisco Secure Firewall Management Center documents two special file-list concepts:

- **Clean List** — treat the listed SHA-256 as clean.
- **Custom Detection List** — treat the listed SHA-256 as malware.

For a false-positive use case, the Clean List is the relevant mechanism.

Typical FMC path documented by Cisco:

```text
Objects
  > Object Management
    > File List
      > Clean List
        > Add by: Enter SHA Value
```

The administrator supplies the complete SHA-256.

Conceptually:

```text
Known-good SHA-256 H1
        |
        v
Cisco FMC Clean List
        |
        v
Treat exact H1 as clean

Different SHA-256 H2
        |
        v
Normal malware evaluation continues
```

That is the central behavioral difference from traditional PAN-OS Antivirus exceptions.

---

## 10. Side-by-Side Comparison

| Capability | PAN-OS File Blocking | PAN-OS traditional Antivirus | PAN-OS WildFire Inline ML | Cisco Secure Firewall/FTD |
|---|---|---|---|---|
| Match file type | Yes | Detection-engine dependent | Model/context dependent | File-policy dependent |
| Match application/direction for file policy | Yes | Application decoder context | Model/context dependent | Policy dependent |
| Exact SHA-256 clean-list for traditional AV false positive | No | No general mechanism documented | Not traditional AV; hash-based ML exception exists | Yes, Clean List |
| Threat-ID exception | No | Yes | Separate mechanism | Different architecture |
| Can File Blocking override AV verdict? | **No** | N/A | N/A | N/A |
| Can a Security rule reduce exception scope? | Indirectly | Yes | Yes | Policy dependent |
| Central management | Panorama | Panorama | Panorama | FMC |
| Primary risk | File-type scope can be broad | Signature exception can affect multiple matching files | Narrower ML-specific file exception | Exact-file scope for clean-list use case |

---

## 11. False Positive vs Signature Collision

Palo Alto Networks uses the term **signature collision** for cases where a benign file is incorrectly identified because its byte patterns or structure match a signature generated for malicious content.

```text
Malicious sample M1
SHA-256 = A
         |
         v
Antivirus signature T123

Benign sample B1
SHA-256 = B
         |
         +--> also matches T123
```

The benign and malicious files can have different SHA-256 values while still triggering the same antivirus signature.

### Why a hash allowlist would be desirable

The desired behavior is:

```text
B is trusted -> allow B only
A is malicious -> continue blocking A
```

Cisco FTD's Clean List maps naturally to this requirement because the exception is based on B's SHA-256.

Traditional PAN-OS Antivirus instead gives the administrator a signature-level exception for `T123`. File Blocking cannot narrow that exception to only `B`.

---

## 12. Recommended PAN-OS Operational Workflow

For a suspected false-positive Antivirus detection:

### Step 1 — Identify the detection source

Go to:

```text
Monitor > Logs > Threat
```

Determine whether the event is associated with conventional Antivirus/WildFire signature handling or WildFire Inline ML.

Relevant threat-log categories can include:

```text
virus
wildfire-virus
ml-virus
```

The remediation path differs by detection type.

### Step 2 — Record evidence

Capture at least:

```text
Threat ID
Threat name
Action
Application
Source / destination
Security rule
Antivirus profile
File name, if available
SHA-256, if available
PAN-OS version
Antivirus content version
WildFire content state
Timestamp
```

### Step 3 — Confirm dynamic content is current

Ensure current Antivirus and WildFire dynamic content is installed before creating a lasting exception. A corrected content release may already resolve the false positive.

### Step 4 — Investigate Threat Vault and WildFire

Use the Threat ID and available file/hash information to determine whether the issue is:

- an incorrect WildFire verdict,
- a conventional Antivirus false positive,
- a signature collision,
- or a WildFire Inline ML false positive.

### Step 5 — Choose the correct exception path

#### Traditional Antivirus false positive / signature collision

Use a Threat-ID Signature Exception only if necessary, preferably temporarily and in a narrowly scoped Antivirus profile.

#### WildFire Inline ML false positive

Use the dedicated File Exception mechanism where appropriate.

#### Incorrect WildFire verdict

Use Palo Alto's incorrect-verdict reporting/support workflow rather than relying on a permanent local exception.

### Step 6 — Do not use File Blocking as an AV bypass

Changing a File Blocking action for PE or another file type does not disable Antivirus inspection.

### Step 7 — Narrow any temporary AV signature exception

Create a dedicated Antivirus profile and attach it only to a tightly scoped Security rule whenever architecture allows.

### Step 8 — Remove the exception after vendor correction

After Palo Alto corrects the signature/verdict in content, remove the local exception and recommit/push the configuration.

---

## 13. Panorama Considerations

In Panorama-managed environments, keep temporary exceptions in the narrowest appropriate **Device Group** and policy scope.

Recommended workflow:

```text
1. Create or clone a dedicated Antivirus profile.
2. Add only the required Threat-ID Signature Exception.
3. Attach it only to the narrow Security Policy rule.
4. Commit to Panorama.
5. Push Device Group configuration to the required firewall(s).
6. Verify the pushed rule/profile on the managed firewall.
7. Remove the exception after content correction.
8. Commit and Push again.
```

Remember the operational distinction:

```text
Commit to Panorama
```

updates Panorama's configuration, while:

```text
Push to Devices
```

sends the applicable Device Group policy/profile configuration to managed firewalls.

Avoid adding a false-positive Threat-ID exception to a broadly inherited/shared Antivirus profile unless that scope is genuinely required.

---

## 14. Verification and Troubleshooting

### Check 1 — Identify the enforcement engine

**Where:** Firewall or Panorama

**Tool:**

```text
Monitor > Logs > Threat
```

**What it tests:** Determines whether the event is traditional Antivirus/WildFire-signature handling or WildFire Inline ML.

**Expected state:** Threat log contains the threat name/ID, action, application, rule, and relevant detection information.

**Failure indicator:** Selecting an exception mechanism before identifying the engine that produced the detection.

**Next action:** Classify the event and use Signature Exception or Inline ML File Exception as appropriate.

### Check 2 — Verify File Blocking separately

**Where:**

```text
Objects > Security Profiles > File Blocking
```

**What it tests:** Determines whether the file type itself is being blocked by File Blocking.

**Expected state:** The matched File Blocking rule/action is understood independently from the Antivirus action.

**Failure indicator:** Assuming a File Blocking non-block action suppresses Antivirus.

**Next action:** Inspect the Antivirus profile referenced by the same Security rule.

### Check 3 — Confirm the Antivirus profile

**Where:**

```text
Objects > Security Profiles > Antivirus
```

**What it tests:** Determines which Antivirus settings and Signature Exceptions apply.

**Expected state:** Only intentionally approved Threat IDs appear as exceptions.

**Failure indicator:** A broadly shared Antivirus profile contains a temporary exception needed only for one business workflow.

**Next action:** Move the exception to a dedicated profile/rule if feasible.

### Check 4 — Verify dynamic content

**Where:**

```text
Device > Dynamic Updates
```

**What it tests:** Ensures an old signature/content package is not causing an already-fixed false positive.

**Expected state:** Antivirus and WildFire content is current for the deployed release/subscriptions.

**Failure indicator:** Old content is installed or scheduled updates are failing.

**Next action:** Correct update connectivity/scheduling and retest.

### Check 5 — Verify Panorama deployment

**Where:** Panorama and managed firewall

**What it tests:** Confirms both Commit and Push completed and the target firewall received the intended profile/rule.

**Expected state:** Managed firewall shows the expected policy/profile assignment.

**Failure indicator:** Change exists on Panorama but not on the firewall.

**Next action:** Review push scope/status and Device Group targeting.

### Check 6 — Retest the file and inspect logs

**What it tests:** Determines whether the expected profile and exception path actually changed enforcement.

**Expected state:** The known-good business flow behaves as intended while unrelated traffic continues to use the strict Antivirus profile.

**Failure indicator:** The same Threat ID still blocks the file, or the exception affects traffic broader than intended.

**Next action:** Recheck Security Policy matching, profile assignment, Panorama push state, content versions, and detection type.

---

## 15. Common Mistakes

- Assuming **File Blocking = malware policy**. PAN-OS File Blocking primarily controls file-transfer policy; Antivirus performs malware signature inspection.
- Allowing `.exe` or another file type in File Blocking and expecting an Antivirus false positive to disappear.
- Assuming File Blocking can match SHA-256.
- Confusing **WildFire Inline ML File Exceptions** with traditional Antivirus Signature Exceptions.
- Adding a Threat-ID exception to an enterprise-wide Antivirus profile when only one application or user population requires temporary relief.
- Treating a filename as cryptographic identity.
- Creating an exception before confirming current Antivirus/WildFire content.
- Failing to remove the exception after Palo Alto corrects the signature.
- Assuming Cisco FMC Clean List behavior has a direct PAN-OS File Blocking equivalent.
- Forgetting that Panorama requires both **Commit** and **Push** for Device Group policy/profile changes to reach managed firewalls.

---

## 16. Design and Risk Implications

The important design difference is **exception granularity**.

### Exact-hash exception

```text
Trust H1 only
```

The exception is bound to one cryptographic file identity.

### PAN-OS traditional AV exception

```text
Do not enforce T123 in this AV profile
```

The exception is bound to the antivirus signature.

### PAN-OS File Blocking rule

```text
Allow/alert/block this file type in this application/direction
```

The rule is bound to file-policy characteristics, not the AV Threat ID or exact SHA-256.

Therefore File Blocking cannot bridge the granularity gap between PAN-OS traditional Antivirus and Cisco's per-hash Clean List model.

The best PAN-OS mitigation when a traditional AV exception is unavoidable is to constrain the affected **traffic scope**, not pretend the exception itself became hash-specific.

---

## 17. Practical Example

Assume:

```text
Known-good file: vendor-agent.exe
SHA-256: H-GOOD
PAN-OS detection: Threat ID 31234
Vendor confirms the binary is legitimate
```

### Desired behavior

```text
H-GOOD -> allow
Any other file matching Threat ID 31234 -> continue blocking
```

### Cisco FTD model

```text
H-GOOD -> FMC Clean List
Other SHA-256 values -> normal malware evaluation
```

### PAN-OS File Blocking attempt

```text
File type: PE
Action: alert / non-block
```

Result:

```text
File Blocking does not block PE
        |
        v
Antivirus still evaluates content
        |
        v
Threat ID 31234 still matches
        |
        v
AV enforcement still occurs
```

### PAN-OS temporary workaround

```text
Security Rule: Approved-Vendor-Agent
  tightly scoped source/user/destination/application
  Antivirus Profile: AV-Vendor-Temporary

AV-Vendor-Temporary
  Signature Exception: Threat ID 31234
```

This reduces exposure to traffic matching `Approved-Vendor-Agent`, but it does **not** create a true `H-GOOD` allowlist.

---

## 18. Key Takeaways

1. **Traditional PAN-OS Antivirus does not provide a general exact-SHA-256 false-positive allowlist equivalent to Cisco FTD's Clean List.**
2. Traditional PAN-OS Antivirus exceptions are **Threat-ID/signature scoped**.
3. **PAN-OS File Blocking cannot be used to create the missing hash-specific AV exception.**
4. File Blocking and Antivirus are separate Security Profiles; allowing a file type does not suppress Antivirus inspection.
5. A dedicated Security rule/profile can **reduce the blast radius** of a Threat-ID exception, but it still cannot match one file by SHA-256.
6. **WildFire Inline ML File Exceptions** are hash/partial-hash based, but they apply to that separate detection path.
7. Cisco FTD/FMC Clean Lists can identify the exact trusted file by full SHA-256, which is the important functional difference for this use case.
8. For PAN-OS traditional AV false positives, the preferred long-term fix is vendor correction of the false positive/signature collision rather than a permanent broad signature exception.

---

## 19. References

### Palo Alto Networks

- **Security Profile: File Blocking**  
  https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles/security-profile-file-blocking

- **Security Profiles** — explains that Security Profiles inspect traffic allowed by Security Policy and describes File Blocking separately from Antivirus  
  https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-profiles

- **Security Profile: Antivirus**  
  https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles/security-profile-antivirus

- **Configure an Antivirus Profile (PAN-OS & Panorama)** — Signature Exceptions and WildFire Inline ML File Exceptions  
  https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles/security-profile-antivirus/configure-an-antivirus-profile-pm

- **Create Threat Exceptions** — Antivirus signature exceptions by Threat ID  
  https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/configure-threat-prevention/create-threat-exceptions

- **Enable Advanced WildFire Inline ML** — File Exceptions for Inline ML false positives  
  https://docs.paloaltonetworks.com/advanced-wildfire/administration/configure-advanced-wildfire-analysis/enable-advanced-wildfire-inline-ml

- **Triage and Resolution of False Positives in Palo Alto Networks Antivirus Profiles**  
  https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000oM8MCAU

- **What is a signature collision?**  
  https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClSOCA0

- **LIVEcommunity**  
  https://live.paloaltonetworks.com/

### Cisco Secure Firewall / FTD comparison

- **Secure Firewall Management Center Device Configuration Guide — Advanced Access Control / File Lists**  
  https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/advanced-access-file.html

---

## Final Decision Matrix

```text
What generated the detection?

Traditional PAN-OS Antivirus signature
        |
        +--> Need exact SHA-256 allowlist?
                 |
                 +--> File Blocking? NO
                 +--> Security Policy hash match? NO
                 +--> AV Signature Exception? YES, but Threat-ID scoped
                 +--> Best long-term action: correct false positive/signature

WildFire Inline ML
        |
        +--> File Exception may be available using hash/partial-hash information

Cisco FTD malware/file policy
        |
        +--> Full SHA-256 Clean List can provide exact-file exception behavior
```
