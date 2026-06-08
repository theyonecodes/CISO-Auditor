# UI/UX Design — CISO Advanced Security Auditor

## Color Palette (GitHub Dark)

```
BG        #0D1117   Window background
BG2       #161B22   Header / toolbar / summary bar
BG3       #1C2128   Treeview container / detail pane
FG        #E6EDF3   Primary text (14.7:1 contrast on BG)
FG2       #8B949E   Secondary / muted text
ACCENT    #58A6FF   Interactive elements, headings, links
GREEN     #3FB950   PASS status
RED       #F85149   FAIL status
AMBER     #D29922   WARNING status
GRAY      #8B949E   PENDING status / disabled
BORDER    #30363D   Frame borders
SCROLL    #484F58   Scrollbar thumb
SCROLL_H  #58A6FF   Scrollbar hover
SELECT_BG #1F3A5F   Treeview row selection
SELECT_FG #FFFFFF   Selected row text
ROW_ALT   #11181C   Alternating row stripe
```

## Layout Structure

```
┌──────────────────────────────────────────────────── WINDOW ──────┐
│ ┌─ HEADER ─────────────────────────────────────────────────────┐ │
│ │ CISO WINDOWS SECURITY AUDITOR                   SCORE: 45% │ │
│ └──────────────────────────────────────────────────────────────┘ │
│ ┌─ TOOLBAR ─────────────────────────────────────────────────────┐ │
│ │ [RUN DEEP SCAN]   [EXPORT REPORT] | Format: ○HTML ○JSON ○CSV │ │
│ │   [FIX ALL] [UNDO]   ████████░░ 80%   Scanning [42/100]...  │ │
│ └──────────────────────────────────────────────────────────────┘ │
│ ┌─ SUMMARY ─────────────────────────────────────────────────────┐ │
│ │  PASS: 30 | FAIL: 22 | WARN: 48 | PENDING: 0                 │ │
│ └──────────────────────────────────────────────────────────────┘ │
│ ┌─ MAIN CONTENT ────────────────────────────────────────────────┐│
│ │ ┌─ TREEVIEW ───────────────────────────────────────────────┐ ││
│ │ │ ID │ Domain     │ Security Check         │Status│Findings │ ││
│ │ │ #01 │ Boot       │ UEFI Secure Boot      │PASS  │Enabled  │ ││
│ │ │ #02 │ Boot       │ TPM 2.0 Status        │PASS  │Ready    │ ││
│ │ │ ...                                                     │ ││
│ │ └──────────────────────────────────────────────────────────┘ ││
│ │ ┌─ DETAIL PANE ────────────────────────────────────────────┐ ││
│ │ │ #042 UAC Prompts                          [ FAIL ]      │ ││
│ │ │ Details: UAC is DISABLED.                               │ ││
│ │ │ Remediation: ⚡ Enable UAC via registry...               │ ││
│ │ │ [APPLY AUTO-FIX]                                        │ ││
│ │ └──────────────────────────────────────────────────────────┘ ││
│ └───────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

## Layout Ratios (1280x820 default)

| Section | Height | Weight |
|---------|--------|--------|
| Header | 56px (fixed) | — |
| Toolbar | auto | — |
| Summary | auto | — |
| Treeview | fills remaining | row 0 weight=1 |
| Detail pane | auto (content-driven) | row 1 weight=0 |

Columns within treeview: ID(50px, fixed) | Domain(2x) | Check(4x) | Status(80px, fixed) | Details(6x)

## Typography

| Context | Font | Size | Weight |
|---------|------|------|--------|
| Title | Segoe UI | 16px | Bold |
| Buttons / labels | Segoe UI | 10px | Bold |
| Body text | Segoe UI | 10px | Normal |
| Treeview content | Consolas | 10px | Normal |
| Treeview headers | Consolas | 10px | Bold |
| Badges | Segoe UI | 9px | Bold |

## Interaction Design

### Scan Flow
1. User clicks **RUN DEEP SCAN**
2. Button changes to `SCANNING...` (disabled, gray)
3. Treeview rows update live — each check shows status as it completes
4. Progress bar fills from 0→100%
5. Score in header updates on completion
6. Summary bar shows final counts
7. EXPORT REPORT + FIX ALL buttons enable

### Fix Flow
1. User selects a FAIL/WARNING row
2. Detail pane shows remediation + **APPLY AUTO-FIX** button (if fixable)
3. User clicks → confirmation dialog → creating restore point → reg write → result
4. Or user clicks **FIX ALL** → confirmation with full change list → batch process
5. **UNDO** button enables after first fix
6. Click UNDO → confirmation → all registry keys restored → checks reset to PENDING

### Export Flow
1. User selects format radio (HTML/JSON/CSV)
2. Clicks **EXPORT REPORT**
3. Save-As dialog appears with correct extension
4. Message box confirms save path

## Responsive Behavior

- Window minimum size: 1024x700
- Treeview columns redistribute at 2:4:6 ratio on resize
- Detail pane text re-wraps dynamically
- Toolbar elements never wrap — right-side cluster stays right-aligned
- Horizontal scrollbar appears if columns exceed treeview width

## Accessibility Choices

| Choice | Rationale |
|--------|-----------|
| FG #E6EDF3 on BG #0D1117 | 14.7:1 contrast ratio (WCAG AAA) |
| Accent #58A6FF on BG #0D1117 | 6.4:1 ratio (WCAG AA) |
| Status colors on #0D1117 | Green 7.9:1, Red 7.1:1, Amber 5.8:1 |
| Selection #1F3A5F + white text | High-contrast selected state |
| Alternating row stripes | Reduces eye strain on long lists |
| Status badges (colored bg + white fg) | Color + text, not color alone |
