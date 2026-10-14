# Supplier Impersonation Monitoring for Microsoft Sentinel

This content pack extends supplier and vendor impersonation monitoring beyond the fixed Defender for Office 365 external domain impersonation list. Customers maintain supplier domains, display names, and lookalike domains in Sentinel watchlists; the workbook and scheduled analytics rules read those same watchlists.

## What is included

| Path | Purpose |
|---|---|
| `arm/workbook.json` | ARM wrapper for the Sentinel workbook resource. |
| `arm/workbook-content.json` | Workbook definition with KQL panels and watchlist guidance. |
| `arm/analytics-rules.json` | Eight separate scheduled analytics rules. |
| `Workbooks/SupplierImpersonationMonitoring.json` | Import-ready Sentinel workbook gallery template. |
| `kql/analytics/*.kql` | Individual rule queries for tuning and review. |
| `watchlists/*.csv` | Sample watchlist schemas and seed rows. |
| `scripts/deploy-content.ps1` | Optional deployment helper for the ARM templates. |

## Data prerequisites

- Microsoft Sentinel enabled on the Log Analytics workspace.
- Microsoft Defender XDR / Microsoft Defender for Office 365 connector sending advanced hunting tables such as `EmailEvents` and `EmailUrlInfo` to Sentinel.
- Three Sentinel watchlists with these aliases:
  - `ProtectedSupplierDomains`
  - `SupplierLookalikeDomains`
  - `SupplierFinancialTerms`

## Watchlist model

### `ProtectedSupplierDomains`

Add one row per supplier domain and display-name alias.

| Column | Description |
|---|---|
| `SearchKey` | Lowercase supplier domain. |
| `SupplierName` | Business-friendly supplier name. |
| `SupplierDomain` | Lowercase allowed sender domain. |
| `DisplayNameKeyword` | Exact lowercase display name to watch for, such as `contoso accounts payable`. Use additional rows for additional aliases. |
| `Criticality` | Optional business criticality. |
| `Notes` | Optional owner or tuning note. |

### `SupplierLookalikeDomains`

Add known registered typo-squats, brand-monitoring results, and threat-intel domains.

### `SupplierFinancialTerms`

Add payment-change and invoice language used by the first-seen sender rule. Subject-only matching is used by default so the rule works with standard MDO telemetry.

## Analytics rules

The ARM template deploys the rules disabled by default so the customer can review thresholds and watchlist content before enabling incidents.

| Rule | Purpose |
|---|---|
| Protected supplier domain with authentication failure | Supplier domain equals a protected domain and authentication evidence indicates SPF, DKIM, DMARC, or composite-auth failure. |
| Known supplier display name from unknown domain | A registered supplier display name is used from a domain not assigned to that supplier. |
| Known registered lookalike domain | Sender domain matches the supplier lookalike watchlist. |
| Generated lookalike domain | Sender domain is algorithmically similar to a protected supplier domain through edit distance, leetspeak-style replacement, TLD swap, prefix/suffix, hyphen insertion, or punycode indicators. |
| First-seen supplier sender with financial language | New sender/domain pair for a supplier uses invoice, payment, bank, remittance, or similar language. |
| High-volume supplier-themed campaign | Multiple recipients receive supplier-themed mail grouped by supplier, sender domain, subject, URL domain, or cluster. |
| Supplier mail with unrelated URL domain | Protected supplier mail contains URLs whose domains do not align to the supplier domain. |
| Delivered threat or remediation activity | Supplier-themed mail is delivered or remediated with suspicious detection metadata. |

## Workbook views

The workbook exposes tracked supplier configuration, top impersonated suppliers, suspicious sender domains, supplier-domain authentication failures, delivery and remediation status, first-seen sender/domain relationships, known and generated lookalike domains, highest-volume recipients, DetectionMethods/ThreatTypes/EmailClusterId trends, and unrelated URL domains.

## Deployment

### Import the workbook template

Use this path when you want to load the workbook directly in Sentinel without deploying the ARM wrapper.

1. Create the three Sentinel watchlists using the CSV files in `watchlists/`.
2. In Microsoft Sentinel, open **Workbooks**, create or open a workbook, select **Edit**, and open **Advanced editor**.
3. Open the **Gallery Template** tab, replace the JSON with `Workbooks/SupplierImpersonationMonitoring.json`, and apply the change.
4. Save the workbook to the Sentinel workspace.

### Deploy with ARM

The helper script expects the Az PowerShell modules used by `Get-AzOperationalInsightsWorkspace` and `New-AzResourceGroupDeployment`.

1. Create the three Sentinel watchlists using the CSV files in `watchlists/`.
2. Deploy the workbook:

```powershell
./scripts/deploy-content.ps1 -ResourceGroupName <rg> -WorkspaceName <workspace> -Location <region> -DeployWorkbook
```

3. Deploy the analytics rules disabled for review:

```powershell
./scripts/deploy-content.ps1 -ResourceGroupName <rg> -WorkspaceName <workspace> -DeployAnalyticsRules
```

4. After validating query results and thresholds, redeploy with `-EnableRules` or enable selected rules in Sentinel.

## Tuning notes

- Display-name matching is exact after lowercase normalization. Add multiple watchlist rows for common supplier aliases.
- Generated lookalike detection is heuristic. It covers likely character replacements, near-edit-distance domains, TLD swaps, supplier-name prefix/suffix domains, hyphen variants, and punycode indicators, but true newly registered domain age still requires registrar, brand-monitoring, or threat-intelligence input in `SupplierLookalikeDomains`.
- The high-volume rule starts with `Recipients >= 5` or `Messages >= 10`; tune this for tenant size.
- The first-seen rule uses a 30-day baseline and a 1-day detection window.
- Authentication detail fields vary by connector and tenant. The rule checks common string patterns in `AuthenticationDetails` plus `AuthenticationStatus` when present.
