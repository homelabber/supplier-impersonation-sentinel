import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_text(relative_path, content):
    path = ROOT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def write_json(relative_path, data):
    path = ROOT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def write_csv(relative_path, rows):
    path = ROOT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


BASE_EMAIL = """let EmailBase = EmailEvents
| extend EventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where EventTime >= ago(QueryPeriod)
| extend SenderDomain = tolower(tostring(column_ifexists("SenderFromDomain", "")))
| extend MailFromDomain = tolower(tostring(column_ifexists("SenderMailFromDomain", "")))
| extend SenderAddress = tolower(tostring(column_ifexists("SenderFromAddress", "")))
| extend SenderDisplayName = tostring(column_ifexists("SenderDisplayName", ""))
| extend Recipient = tolower(tostring(column_ifexists("RecipientEmailAddress", "")))
| extend SubjectText = tostring(column_ifexists("Subject", ""))
| extend SubjectNormalized = replace_regex(tolower(SubjectText), @"\\s+", " ")
| extend NetworkMessageId = tostring(column_ifexists("NetworkMessageId", ""))
| extend DeliveryAction = tostring(column_ifexists("DeliveryAction", ""))
| extend DeliveryLocation = tostring(column_ifexists("DeliveryLocation", ""))
| extend ThreatTypes = tostring(column_ifexists("ThreatTypes", ""))
| extend DetectionMethods = tostring(column_ifexists("DetectionMethods", ""))
| extend EmailClusterId = tostring(column_ifexists("EmailClusterId", ""))
| extend AuthRaw = tolower(tostring(column_ifexists("AuthenticationDetails", "")));
let ProtectedSuppliers = _GetWatchlist('ProtectedSupplierDomains')
| extend SupplierDomain = tolower(coalesce(tostring(SupplierDomain), tostring(SearchKey)))
| extend DisplayNameKeyword = tolower(tostring(DisplayNameKeyword))
| project SupplierName, SupplierDomain, DisplayNameKeyword, Criticality, Notes;"""

WORKBOOK_BASE_EMAIL = BASE_EMAIL.replace("| where EventTime >= ago(QueryPeriod)", "| where EventTime {TimeRange}")


AUTH_FAILURE_QUERY = BASE_EMAIL + """
EmailBase
| join kind=inner (ProtectedSuppliers | summarize arg_max(Criticality, *) by SupplierDomain) on $left.SenderDomain == $right.SupplierDomain
| where AuthRaw has_any ('dmarc:fail', '"dmarc":"fail"', 'dmarc=fail', 'compauth:fail', '"compauth":"fail"', 'spf:fail', '"spf":"fail"', 'dkim:fail', '"dkim":"fail"', 'authentication failed', 'composite authentication failed')
    or tostring(column_ifexists("AuthenticationStatus", "")) has_any ("fail", "failed")
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 10), Subjects=make_set(SubjectText, 10), DeliveryLocations=make_set(DeliveryLocation, 10), ThreatTypes=make_set(ThreatTypes, 10), DetectionMethods=make_set(DetectionMethods, 10), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SupplierName, SupplierDomain, SenderAddress, SenderDomain, MailFromDomain, Criticality
| extend AccountCustomEntity = tostring(SampleRecipients[0]), SenderCustomEntity = SenderAddress, DNSCustomEntity = SenderDomain
| order by Recipients desc, Messages desc"""


DISPLAY_NAME_QUERY = BASE_EMAIL + """
EmailBase
| extend DisplayNameNormalized = tolower(trim(@" ", SenderDisplayName))
| where isnotempty(DisplayNameNormalized)
| join kind=inner (ProtectedSuppliers | where isnotempty(DisplayNameKeyword) | summarize arg_max(Criticality, *) by SupplierName, DisplayNameKeyword) on $left.DisplayNameNormalized == $right.DisplayNameKeyword
| join kind=leftanti (ProtectedSuppliers | project SupplierName, SenderDomain=SupplierDomain) on SupplierName, SenderDomain
| summarize Messages=count(), Recipients=dcount(Recipient), SenderAddresses=make_set(SenderAddress, 20), SenderDomains=make_set(SenderDomain, 20), Subjects=make_set(SubjectText, 10), DeliveryLocations=make_set(DeliveryLocation, 10), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SupplierName, SenderDisplayName, DisplayNameKeyword, Criticality
| extend AccountCustomEntity = tostring(SenderAddresses[0]), DNSCustomEntity = tostring(SenderDomains[0])
| order by Recipients desc, Messages desc"""


LOOKALIKE_QUERY = BASE_EMAIL + """
let Lookalikes = _GetWatchlist('SupplierLookalikeDomains')
| extend LookalikeDomain = tolower(coalesce(tostring(LookalikeDomain), tostring(SearchKey)))
| extend ProtectedSupplierDomain = tolower(tostring(ProtectedSupplierDomain))
| project ProtectedSupplierName, ProtectedSupplierDomain, LookalikeDomain, Source, FirstSeen, Notes;
EmailBase
| join kind=inner (Lookalikes) on $left.SenderDomain == $right.LookalikeDomain
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 10), SenderAddresses=make_set(SenderAddress, 20), Subjects=make_set(SubjectText, 10), DeliveryLocations=make_set(DeliveryLocation, 10), ThreatTypes=make_set(ThreatTypes, 10), DetectionMethods=make_set(DetectionMethods, 10), FirstMessage=min(EventTime), LastMessage=max(EventTime) by ProtectedSupplierName, ProtectedSupplierDomain, LookalikeDomain, Source, FirstSeen, Notes
| extend SupplierName = ProtectedSupplierName
| extend AccountCustomEntity = tostring(SampleRecipients[0]), DNSCustomEntity = LookalikeDomain
| order by Recipients desc, Messages desc"""


GENERATED_LOOKALIKE_QUERY = """let QueryPeriod = 1h;
let BaselinePeriod = 30d;
let compact = (value:string) { replace_regex(tolower(value), @"[^a-z0-9]", "") };
let skeleton = (value:string) {
    replace_string(
        replace_string(
            replace_string(
                replace_string(
                    replace_string(
                        replace_string(compact(value), "0", "o"),
                    "1", "l"),
                "3", "e"),
            "4", "a"),
        "5", "s"),
    "8", "b")
};
let ProtectedSuppliers = _GetWatchlist('ProtectedSupplierDomains')
| extend SupplierDomain = tolower(coalesce(tostring(SupplierDomain), tostring(SearchKey)))
| where isnotempty(SupplierDomain)
| extend ProtectedRawRoot = tostring(split(SupplierDomain, ".")[0])
| extend ProtectedRoot = compact(ProtectedRawRoot)
| extend ProtectedSkeleton = skeleton(ProtectedRawRoot)
| where strlen(ProtectedRoot) >= 5
| summarize arg_max(Criticality, *) by SupplierName, SupplierDomain, ProtectedRawRoot, ProtectedRoot, ProtectedSkeleton;
let BaselineDomains =
EmailEvents
| extend EventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where EventTime between (ago(BaselinePeriod + QueryPeriod) .. ago(QueryPeriod))
| extend SenderDomain = tolower(tostring(column_ifexists("SenderFromDomain", "")))
| summarize by SenderDomain;
let CurrentSenderDomains =
EmailEvents
| extend EventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where EventTime >= ago(QueryPeriod)
| extend SenderDomain = tolower(tostring(column_ifexists("SenderFromDomain", "")))
| extend SenderAddress = tolower(tostring(column_ifexists("SenderFromAddress", "")))
| extend SenderDisplayName = tostring(column_ifexists("SenderDisplayName", ""))
| extend Recipient = tolower(tostring(column_ifexists("RecipientEmailAddress", "")))
| extend SubjectText = tostring(column_ifexists("Subject", ""))
| extend DeliveryLocation = tostring(column_ifexists("DeliveryLocation", ""))
| extend ThreatTypes = tostring(column_ifexists("ThreatTypes", ""))
| extend DetectionMethods = tostring(column_ifexists("DetectionMethods", ""))
| where isnotempty(SenderDomain)
| where SenderDomain !in ((ProtectedSuppliers | project SupplierDomain))
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 10), SenderAddresses=make_set(SenderAddress, 20), DisplayNames=make_set(SenderDisplayName, 10), Subjects=make_set(SubjectText, 10), DeliveryLocations=make_set(DeliveryLocation, 10), ThreatTypes=make_set(ThreatTypes, 10), DetectionMethods=make_set(DetectionMethods, 10), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SenderDomain
| extend SenderRawRoot = tostring(split(SenderDomain, ".")[0])
| extend SenderRoot = compact(SenderRawRoot)
| extend SenderSkeleton = skeleton(SenderRawRoot)
| where strlen(SenderRoot) >= 5;
CurrentSenderDomains
| extend JoinKey = 1
| join kind=inner (ProtectedSuppliers | extend JoinKey = 1) on JoinKey
| extend RootDistance = edit_distance(SenderRoot, ProtectedRoot)
| extend SkeletonDistance = edit_distance(SenderSkeleton, ProtectedSkeleton)
| extend IsTldSwap = SenderRoot == ProtectedRoot and SenderDomain != SupplierDomain
| extend IsSmallEdit = abs(strlen(SenderRoot) - strlen(ProtectedRoot)) <= 2 and RootDistance between (1 .. 2)
| extend IsCharacterReplacement = SenderSkeleton == ProtectedSkeleton and SenderRoot != ProtectedRoot
| extend IsNearSkeleton = SkeletonDistance == 1 and RootDistance <= 3
| extend IsAffixedBrand = SenderRoot != ProtectedRoot and strlen(SenderRoot) <= strlen(ProtectedRoot) + 12 and (SenderRoot startswith ProtectedRoot or SenderRoot endswith ProtectedRoot)
| extend IsHyphenVariant = SenderRawRoot contains "-" and replace_string(tolower(SenderRawRoot), "-", "") == tolower(ProtectedRawRoot)
| extend IsPunycode = SenderDomain startswith "xn--" or SenderDomain contains ".xn--"
| where IsTldSwap or IsSmallEdit or IsCharacterReplacement or IsNearSkeleton or IsAffixedBrand or IsHyphenVariant
| join kind=leftouter (BaselineDomains | extend SeenInBaseline = true) on SenderDomain
| extend BaselineStatus = iff(SeenInBaseline == true, "Previously observed in baseline", "New sender domain in baseline window")
| extend LookalikeReason = trim(@", ", strcat(
    iff(IsTldSwap, "same root with different TLD, ", ""),
    iff(IsSmallEdit, "small edit distance, ", ""),
    iff(IsCharacterReplacement, "character replacement/leetspeak skeleton match, ", ""),
    iff(IsNearSkeleton, "near skeleton match, ", ""),
    iff(IsAffixedBrand, "supplier name with prefix/suffix, ", ""),
    iff(IsHyphenVariant, "hyphen insertion variant, ", ""),
    iff(IsPunycode, "punycode/IDN indicator, ", ""),
    BaselineStatus))
| extend Score = 100 - (RootDistance * 10) + iff(IsCharacterReplacement, 20, 0) + iff(IsTldSwap, 15, 0) + iff(SeenInBaseline == true, 0, 10)
| summarize arg_max(Score, *) by SupplierName, SupplierDomain, SenderDomain
| extend AccountCustomEntity = tostring(SampleRecipients[0]), DNSCustomEntity = SenderDomain
| project SupplierName, SupplierDomain, Criticality, SenderDomain, LookalikeReason, RootDistance, SkeletonDistance, Score, BaselineStatus, Messages, Recipients, SampleRecipients, SenderAddresses, DisplayNames, Subjects, DeliveryLocations, ThreatTypes, DetectionMethods, FirstSeen, LastSeen, AccountCustomEntity, DNSCustomEntity
| order by Score desc, Recipients desc, Messages desc"""


FIRST_SEEN_QUERY = """let QueryPeriod = 1d;
let BaselinePeriod = 30d;
let ProtectedSuppliers = _GetWatchlist('ProtectedSupplierDomains')
| extend SupplierDomain = tolower(coalesce(tostring(SupplierDomain), tostring(SearchKey)))
| summarize by SupplierName, SupplierDomain, Criticality;
let FinancialTerms = _GetWatchlist('SupplierFinancialTerms')
| extend Term = tolower(coalesce(tostring(Term), tostring(SearchKey)))
| summarize Terms=make_set(Term, 500);
let Baseline =
EmailEvents
| extend EventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where EventTime between (ago(BaselinePeriod + QueryPeriod) .. ago(QueryPeriod))
| extend SenderDomain = tolower(tostring(column_ifexists("SenderFromDomain", "")))
| extend SenderAddress = tolower(tostring(column_ifexists("SenderFromAddress", "")))
| summarize by SenderAddress, SenderDomain;
EmailEvents
| extend EventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where EventTime >= ago(QueryPeriod)
| extend SenderDomain = tolower(tostring(column_ifexists("SenderFromDomain", "")))
| extend SenderAddress = tolower(tostring(column_ifexists("SenderFromAddress", "")))
| extend Recipient = tolower(tostring(column_ifexists("RecipientEmailAddress", "")))
| extend SubjectText = tostring(column_ifexists("Subject", ""))
| extend SubjectLower = tolower(SubjectText)
| where SubjectLower has_any (toscalar(FinancialTerms))
| join kind=inner (ProtectedSuppliers) on $left.SenderDomain == $right.SupplierDomain
| join kind=leftanti Baseline on SenderAddress, SenderDomain
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 10), Subjects=make_set(SubjectText, 10), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SupplierName, SupplierDomain, SenderAddress, Criticality
| extend AccountCustomEntity = tostring(SampleRecipients[0]), SenderCustomEntity = SenderAddress, DNSCustomEntity = SupplierDomain
| order by Recipients desc, Messages desc"""


HIGH_VOLUME_QUERY = BASE_EMAIL + """
let Urls = EmailUrlInfo
| extend UrlEventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where UrlEventTime >= ago(QueryPeriod)
| extend NetworkMessageId = tostring(column_ifexists("NetworkMessageId", ""))
| extend UrlDomain = tolower(tostring(column_ifexists("UrlDomain", "")))
| summarize UrlDomains=make_set(UrlDomain, 20) by NetworkMessageId;
EmailBase
| join kind=inner (ProtectedSuppliers | summarize arg_max(Criticality, *) by SupplierDomain) on $left.SenderDomain == $right.SupplierDomain
| join kind=leftouter Urls on NetworkMessageId
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 20), SenderAddresses=make_set(SenderAddress, 20), UrlDomains=make_set(UrlDomains, 20), DeliveryLocations=make_set(DeliveryLocation, 10), ThreatTypes=make_set(ThreatTypes, 10), DetectionMethods=make_set(DetectionMethods, 10), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SupplierName, SupplierDomain, SubjectNormalized, EmailClusterId, Criticality
| where Recipients >= 5 or Messages >= 10
| extend AccountCustomEntity = tostring(SampleRecipients[0]), DNSCustomEntity = SupplierDomain
| order by Recipients desc, Messages desc"""


URL_MISMATCH_QUERY = BASE_EMAIL + """
let Urls = EmailUrlInfo
| extend UrlEventTime = coalesce(column_ifexists("TimeGenerated", datetime(null)), column_ifexists("Timestamp", datetime(null)))
| where UrlEventTime >= ago(QueryPeriod)
| extend NetworkMessageId = tostring(column_ifexists("NetworkMessageId", ""))
| extend Url = tostring(column_ifexists("Url", ""))
| extend UrlDomain = tolower(tostring(column_ifexists("UrlDomain", "")))
| where isnotempty(UrlDomain)
| summarize Urls=make_set(Url, 20), UrlDomains=make_set(UrlDomain, 20) by NetworkMessageId;
EmailBase
| join kind=inner (ProtectedSuppliers | summarize arg_max(Criticality, *) by SupplierDomain) on $left.SenderDomain == $right.SupplierDomain
| join kind=inner Urls on NetworkMessageId
| mv-expand UrlDomain = UrlDomains to typeof(string)
| where UrlDomain !endswith SupplierDomain
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 10), Subjects=make_set(SubjectText, 10), UrlDomains=make_set(UrlDomain, 20), Urls=make_set(Urls, 20), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SupplierName, SupplierDomain, SenderAddress, Criticality
| where Recipients >= 2 or Messages >= 3
| extend AccountCustomEntity = tostring(SampleRecipients[0]), SenderCustomEntity = SenderAddress, DNSCustomEntity = tostring(UrlDomains[0]), URLCustomEntity = tostring(Urls[0])
| order by Recipients desc, Messages desc"""


POST_DELIVERY_QUERY = BASE_EMAIL + """
EmailBase
| join kind=inner (ProtectedSuppliers | summarize arg_max(Criticality, *) by SupplierDomain) on $left.SenderDomain == $right.SupplierDomain
| where DeliveryLocation in~ ("Inbox/folder", "Junk folder", "Deleted items", "Quarantine", "Hosted quarantine")
| where DeliveryAction in~ ("Delivered", "Junked", "Blocked") or ThreatTypes !in ("", "Spam")
| summarize Messages=count(), Recipients=dcount(Recipient), SampleRecipients=make_set(Recipient, 20), Subjects=make_set(SubjectText, 10), ThreatTypes=make_set(ThreatTypes, 10), DetectionMethods=make_set(DetectionMethods, 10), DeliveryLocations=make_set(DeliveryLocation, 10), FirstSeen=min(EventTime), LastSeen=max(EventTime) by SupplierName, SupplierDomain, SenderAddress, Criticality
| where Messages >= 3 or Recipients >= 2
| extend AccountCustomEntity = tostring(SampleRecipients[0]), SenderCustomEntity = SenderAddress, DNSCustomEntity = SupplierDomain
| order by Recipients desc, Messages desc"""


ANALYTICS = [
    {
        "id": "supplier-domain-authentication-failure",
        "displayName": "Supplier impersonation - protected supplier domain with authentication failure",
        "description": "Visible sender domain is in the protected supplier watchlist, but authentication evidence indicates DMARC, SPF, DKIM, or composite authentication failure.",
        "severity": "High",
        "query": "let QueryPeriod = 1h;\n" + AUTH_FAILURE_QUERY,
        "frequency": "PT1H",
        "period": "PT1H",
        "tactics": ["InitialAccess", "CredentialAccess"],
        "techniques": ["T1566"],
    },
    {
        "id": "supplier-display-name-unknown-domain",
        "displayName": "Supplier impersonation - known supplier display name from unknown domain",
        "description": "A display name registered to a protected supplier is used from a sender domain not assigned to that supplier.",
        "severity": "Medium",
        "query": "let QueryPeriod = 1h;\n" + DISPLAY_NAME_QUERY,
        "frequency": "PT1H",
        "period": "PT1H",
        "tactics": ["InitialAccess"],
        "techniques": ["T1566"],
    },
    {
        "id": "supplier-registered-lookalike-domain",
        "displayName": "Supplier impersonation - known registered lookalike domain",
        "description": "SenderFromDomain matches a domain in the supplier lookalike watchlist, such as brand-monitoring or typosquat intelligence.",
        "severity": "High",
        "query": "let QueryPeriod = 1h;\n" + LOOKALIKE_QUERY,
        "frequency": "PT1H",
        "period": "PT1H",
        "tactics": ["InitialAccess"],
        "techniques": ["T1566"],
    },
    {
        "id": "supplier-generated-lookalike-domain",
        "displayName": "Supplier impersonation - generated lookalike domain",
        "description": "SenderFromDomain is algorithmically similar to a protected supplier domain using edit distance, character replacement, TLD swap, prefix/suffix, hyphen insertion, or punycode indicators.",
        "severity": "Medium",
        "query": GENERATED_LOOKALIKE_QUERY,
        "frequency": "PT1H",
        "period": "P31D",
        "tactics": ["InitialAccess"],
        "techniques": ["T1566"],
    },
    {
        "id": "supplier-first-seen-financial-language",
        "displayName": "Supplier impersonation - first-seen supplier sender with financial language",
        "description": "A new sender/domain relationship for a protected supplier uses invoice, payment, bank, or remittance language in the subject.",
        "severity": "Medium",
        "query": FIRST_SEEN_QUERY,
        "frequency": "P1D",
        "period": "P31D",
        "tactics": ["InitialAccess", "Impact"],
        "techniques": ["T1566"],
    },
    {
        "id": "supplier-high-volume-campaign",
        "displayName": "Supplier impersonation - high-volume supplier-themed campaign",
        "description": "Multiple recipients received supplier-themed mail with common sender domain, subject, URL domain, or email cluster.",
        "severity": "High",
        "query": "let QueryPeriod = 1h;\n" + HIGH_VOLUME_QUERY,
        "frequency": "PT1H",
        "period": "PT1H",
        "tactics": ["InitialAccess"],
        "techniques": ["T1566"],
    },
    {
        "id": "supplier-url-domain-mismatch",
        "displayName": "Supplier impersonation - protected supplier mail with unrelated URL domain",
        "description": "A protected supplier domain sent mail containing URLs whose domains do not align to the supplier domain, useful for payment portal and credential-harvest triage.",
        "severity": "Medium",
        "query": "let QueryPeriod = 1h;\n" + URL_MISMATCH_QUERY,
        "frequency": "PT1H",
        "period": "PT1H",
        "tactics": ["InitialAccess", "CredentialAccess"],
        "techniques": ["T1566", "T1556"],
    },
    {
        "id": "supplier-delivered-threat-or-remediation",
        "displayName": "Supplier impersonation - delivered supplier-themed threat or remediation activity",
        "description": "Protected supplier mail has suspicious verdicts, detection methods, threat types, or remediation-relevant delivery locations.",
        "severity": "Medium",
        "query": "let QueryPeriod = 1h;\n" + POST_DELIVERY_QUERY,
        "frequency": "PT1H",
        "period": "PT1H",
        "tactics": ["InitialAccess"],
        "techniques": ["T1566"],
    },
]


WORKBOOK_QUERIES = {
    "tracked-suppliers": """_GetWatchlist('ProtectedSupplierDomains')
| extend SupplierDomain = tolower(coalesce(tostring(SupplierDomain), tostring(SearchKey)))
| summarize Domains=dcount(SupplierDomain), DisplayNames=dcountif(DisplayNameKeyword, isnotempty(DisplayNameKeyword)), Criticalities=make_set(Criticality, 10), Notes=make_set(Notes, 5) by SupplierName
| order by Domains desc, SupplierName asc""",
    "top-impersonated-suppliers": HIGH_VOLUME_QUERY.replace(BASE_EMAIL, WORKBOOK_BASE_EMAIL).replace("| where UrlEventTime >= ago(QueryPeriod)", "| where UrlEventTime {TimeRange}") + """
| summarize Messages=sum(Messages), Recipients=sum(Recipients), SenderDomains=make_set(SenderDomain, 20), SampleSubjects=make_set(SubjectNormalized, 10) by SupplierName, Criticality
| top 20 by Recipients desc, Messages desc""",
    "suspicious-sender-domains": WORKBOOK_BASE_EMAIL + """
EmailBase
| join kind=leftouter (ProtectedSuppliers | summarize by SupplierDomain, SupplierName) on $left.SenderDomain == $right.SupplierDomain
| where isnotempty(SupplierName) or SenderDisplayName has_any ((_GetWatchlist('ProtectedSupplierDomains') | where isnotempty(DisplayNameKeyword) | summarize make_set(DisplayNameKeyword, 500)))
| summarize Messages=count(), Recipients=dcount(Recipient), Suppliers=make_set(SupplierName, 10), ThreatTypes=make_set(ThreatTypes, 10), DetectionMethods=make_set(DetectionMethods, 10) by SenderDomain
| top 25 by Recipients desc, Messages desc""",
    "auth-failures": AUTH_FAILURE_QUERY.replace(BASE_EMAIL, WORKBOOK_BASE_EMAIL),
    "delivery-remediation": WORKBOOK_BASE_EMAIL + """
EmailBase
| join kind=inner (ProtectedSuppliers | summarize by SupplierDomain, SupplierName) on $left.SenderDomain == $right.SupplierDomain
| summarize Messages=count(), Recipients=dcount(Recipient) by SupplierName, DeliveryAction, DeliveryLocation
| order by Messages desc""",
    "generated-lookalikes": GENERATED_LOOKALIKE_QUERY.replace("| where EventTime >= ago(QueryPeriod)", "| where EventTime {TimeRange}"),
    "first-seen": FIRST_SEEN_QUERY,
    "lookalikes": LOOKALIKE_QUERY.replace(BASE_EMAIL, WORKBOOK_BASE_EMAIL),
    "top-recipients": WORKBOOK_BASE_EMAIL + """
EmailBase
| join kind=inner (ProtectedSuppliers | summarize by SupplierDomain, SupplierName) on $left.SenderDomain == $right.SupplierDomain
| summarize Messages=count(), SupplierCount=dcount(SupplierName), Suppliers=make_set(SupplierName, 20), SenderDomains=make_set(SenderDomain, 20), DeliveryLocations=make_set(DeliveryLocation, 10) by Recipient
| top 25 by Messages desc""",
    "trends-detection": WORKBOOK_BASE_EMAIL + """
EmailBase
| join kind=inner (ProtectedSuppliers | summarize by SupplierDomain, SupplierName) on $left.SenderDomain == $right.SupplierDomain
| summarize Messages=count() by bin(EventTime, 1d), DetectionMethods, ThreatTypes, EmailClusterId
| order by EventTime asc""",
    "url-domains": URL_MISMATCH_QUERY.replace(BASE_EMAIL, WORKBOOK_BASE_EMAIL).replace("| where UrlEventTime >= ago(QueryPeriod)", "| where UrlEventTime {TimeRange}"),
}


def analytics_template():
    resources = []
    for rule in ANALYTICS:
        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "apiVersion": "[variables('securityInsightsApiVersion')]",
                "name": f"[format('{{0}}/Microsoft.SecurityInsights/{{1}}', parameters('workspaceName'), guid(parameters('workspaceName'), '{rule['id']}'))]",
                "kind": "Scheduled",
                "properties": {
                    "displayName": rule["displayName"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "enabled": "[parameters('enableRules')]",
                    "query": rule["query"],
                    "queryFrequency": rule["frequency"],
                    "queryPeriod": rule["period"],
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "suppressionDuration": "PT5H",
                    "suppressionEnabled": False,
                    "tactics": rule["tactics"],
                    "techniques": rule["techniques"],
                    "entityMappings": [
                        {
                            "entityType": "Mailbox",
                            "fieldMappings": [
                                {
                                    "identifier": "MailboxPrimaryAddress",
                                    "columnName": "AccountCustomEntity",
                                }
                            ],
                        },
                        {
                            "entityType": "DNS",
                            "fieldMappings": [
                                {
                                    "identifier": "DomainName",
                                    "columnName": "DNSCustomEntity",
                                }
                            ],
                        },
                    ],
                    "customDetails": {
                        "SupplierName": "SupplierName",
                        "ImpersonationDomain": "DNSCustomEntity",
                        "MessageCount": "Messages",
                        "RecipientCount": "Recipients",
                    },
                    "incidentConfiguration": {
                        "createIncident": True,
                        "groupingConfiguration": {
                            "enabled": True,
                            "reopenClosedIncident": False,
                            "lookbackDuration": "PT5H",
                            "matchingMethod": "Selected",
                            "groupByEntities": ["DNS", "Mailbox"],
                            "groupByCustomDetails": ["SupplierName", "ImpersonationDomain"],
                        },
                    },
                    "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
                },
            }
        )

    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": "Microsoft Sentinel scheduled analytics rules for supplier impersonation monitoring using Microsoft Defender for Office 365 EmailEvents, EmailUrlInfo, and Sentinel watchlists."
        },
        "parameters": {
            "workspaceName": {
                "type": "string",
                "metadata": {"description": "Name of the Sentinel-enabled Log Analytics workspace."},
            },
            "enableRules": {
                "type": "bool",
                "defaultValue": False,
                "metadata": {"description": "Set true to deploy rules enabled. Default is disabled for review and tuning."},
            },
        },
        "variables": {"securityInsightsApiVersion": "2023-02-01"},
        "resources": resources,
    }


def workbook_content():
    def text(name, markdown):
        return {"type": 1, "name": name, "content": {"json": markdown}}

    def kql(name, title, query, visualization="grid", width=None):
        item = {
            "type": 3,
            "name": name,
            "content": {
                "version": "KqlItem/1.0",
                "title": title,
                "query": query,
                "size": 0,
                "timeContextFromParameter": "TimeRange",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": visualization,
            },
        }
        if width:
            item["customWidth"] = width
        return item

    items = [
        text(
            "title",
            "# Supplier Impersonation Monitoring\nUse Sentinel watchlists to extend beyond the Defender for Office 365 external domain impersonation limit. The same watchlists drive this workbook and the analytics rules.",
        ),
        {
            "type": 9,
            "name": "parameters",
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": "p-timerange",
                        "version": "KqlParameterItem/1.0",
                        "name": "TimeRange",
                        "label": "Time range",
                        "type": 4,
                        "isRequired": True,
                        "value": {"durationMs": 604800000},
                        "typeSettings": {
                            "selectableValues": [
                                {"durationMs": 3600000},
                                {"durationMs": 14400000},
                                {"durationMs": 43200000},
                                {"durationMs": 86400000},
                                {"durationMs": 604800000},
                                {"durationMs": 2592000000},
                            ]
                        },
                    }
                ],
            },
        },
        text(
            "watchlist-guidance",
            "## Watchlist-driven configuration\nAdd supplier domains to the `ProtectedSupplierDomains` watchlist. Add registered typo-squats or monitored brand domains to `SupplierLookalikeDomains`. Add payment-change language to `SupplierFinancialTerms`. No workbook edit is required after the watchlists are updated.",
        ),
        kql("tracked-suppliers", "Tracked suppliers and configured domains", WORKBOOK_QUERIES["tracked-suppliers"], "grid"),
        kql("top-impersonated-suppliers", "Top impersonated suppliers", WORKBOOK_QUERIES["top-impersonated-suppliers"], "barchart", "50"),
        kql("suspicious-sender-domains", "Messages by suspicious sender domain", WORKBOOK_QUERIES["suspicious-sender-domains"], "barchart", "50"),
        kql("auth-failures", "Supplier-domain authentication failures", WORKBOOK_QUERIES["auth-failures"], "grid"),
        kql("delivery-remediation", "Delivery location and remediation status", WORKBOOK_QUERIES["delivery-remediation"], "piechart", "50"),
        kql("first-seen", "First-seen supplier sender/domain relationships with financial language", WORKBOOK_QUERIES["first-seen"], "grid", "50"),
        kql("lookalikes", "Lookalike domains by protected supplier", WORKBOOK_QUERIES["lookalikes"], "grid"),
        kql("generated-lookalikes", "Generated lookalike domains by protected supplier", WORKBOOK_QUERIES["generated-lookalikes"], "grid"),
        kql("top-recipients", "Users receiving the most supplier-themed messages", WORKBOOK_QUERIES["top-recipients"], "barchart", "50"),
        kql("trends-detection", "Trends by DetectionMethods, ThreatTypes, and EmailClusterId", WORKBOOK_QUERIES["trends-detection"], "timechart", "50"),
        kql("url-domains", "Supplier mail with unrelated URL domains", WORKBOOK_QUERIES["url-domains"], "grid"),
    ]
    return {
        "version": "Notebook/1.0",
        "isLocked": False,
        "fallbackResourceIds": ["__WORKSPACE_ID__"],
        "items": items,
    }


def workbook_template():
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": "Deploys the Supplier Impersonation Monitoring workbook into a Microsoft Sentinel workspace."
        },
        "parameters": {
            "workbookDisplayName": {
                "type": "string",
                "defaultValue": "Supplier Impersonation Monitoring",
                "metadata": {"description": "Display name shown in Sentinel/Monitor Workbooks."},
            },
            "workbookId": {
                "type": "string",
                "metadata": {"description": "A GUID for the workbook resource name."},
            },
            "location": {
                "type": "string",
                "metadata": {"description": "Region for the workbook resource."},
            },
            "workspaceResourceId": {
                "type": "string",
                "metadata": {"description": "Full resource ID of the Log Analytics workspace."},
            },
            "serializedData": {
                "type": "string",
                "metadata": {"description": "Stringified workbook-content.json."},
            },
        },
        "resources": [
            {
                "type": "microsoft.insights/workbooks",
                "apiVersion": "2022-04-01",
                "name": "[parameters('workbookId')]",
                "location": "[parameters('location')]",
                "kind": "shared",
                "properties": {
                    "displayName": "[parameters('workbookDisplayName')]",
                    "serializedData": "[parameters('serializedData')]",
                    "version": "1.0",
                    "sourceId": "[parameters('workspaceResourceId')]",
                    "category": "sentinel",
                },
            }
        ],
    }


README = """# Supplier Impersonation Monitoring for Microsoft Sentinel

This content pack extends supplier and vendor impersonation monitoring beyond the fixed Defender for Office 365 external domain impersonation list. Customers maintain supplier domains, display names, and lookalike domains in Sentinel watchlists; the workbook and scheduled analytics rules read those same watchlists.

## What is included

| Path | Purpose |
|---|---|
| `arm/workbook.json` | ARM wrapper for the Sentinel workbook resource. |
| `arm/workbook-content.json` | Workbook definition with KQL panels and watchlist guidance. |
| `arm/analytics-rules.json` | Eight separate scheduled analytics rules. |
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
"""


DEPLOY_PS1 = r"""[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [string]$Location,

    [switch]$DeployWorkbook,

    [switch]$DeployAnalyticsRules,

    [switch]$EnableRules
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

if (-not $DeployWorkbook -and -not $DeployAnalyticsRules) {
    throw "Specify -DeployWorkbook, -DeployAnalyticsRules, or both."
}

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
if (-not $Location) {
    $Location = $workspace.Location
}

if ($DeployWorkbook) {
    $seed = "$($workspace.ResourceId)|supplier-impersonation-monitoring"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $workbookId = ([Guid]::new($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed)))).Guid
    $contentPath = Join-Path $root 'arm\workbook-content.json'
    $serializedData = Get-Content -LiteralPath $contentPath -Raw
    New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile (Join-Path $root 'arm\workbook.json') `
        -workbookDisplayName 'Supplier Impersonation Monitoring' `
        -workbookId $workbookId `
        -location $Location `
        -workspaceResourceId $workspace.ResourceId `
        -serializedData $serializedData
}

if ($DeployAnalyticsRules) {
    New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile (Join-Path $root 'arm\analytics-rules.json') `
        -workspaceName $WorkspaceName `
        -enableRules ([bool]$EnableRules)
}
"""


def main():
    write_json("arm/analytics-rules.json", analytics_template())
    write_json("arm/workbook.json", workbook_template())
    write_json("arm/workbook-content.json", workbook_content())
    write_text("README.md", README)
    write_text("scripts/deploy-content.ps1", DEPLOY_PS1)

    for rule in ANALYTICS:
        write_text(f"kql/analytics/{rule['id']}.kql", rule["query"])

    for name, query in WORKBOOK_QUERIES.items():
        write_text(f"kql/workbook/{name}.kql", query)

    write_csv(
        "watchlists/ProtectedSupplierDomains.csv",
        [
            {
                "SearchKey": "contoso-supplier.example",
                "SupplierName": "Contoso Supplier",
                "SupplierDomain": "contoso-supplier.example",
                "DisplayNameKeyword": "contoso accounts payable",
                "Criticality": "High",
                "Notes": "Sample row. Replace with customer supplier domains.",
            },
            {
                "SearchKey": "fabrikam-vendor.example",
                "SupplierName": "Fabrikam Vendor",
                "SupplierDomain": "fabrikam-vendor.example",
                "DisplayNameKeyword": "fabrikam billing",
                "Criticality": "Medium",
                "Notes": "Sample row. Add one row per display-name alias.",
            },
        ],
    )
    write_csv(
        "watchlists/SupplierLookalikeDomains.csv",
        [
            {
                "SearchKey": "contoso-supp1ier.example",
                "ProtectedSupplierName": "Contoso Supplier",
                "ProtectedSupplierDomain": "contoso-supplier.example",
                "LookalikeDomain": "contoso-supp1ier.example",
                "Source": "Brand monitoring",
                "FirstSeen": "2026-10-01",
                "Notes": "Sample typo-squat.",
            }
        ],
    )
    write_csv(
        "watchlists/SupplierFinancialTerms.csv",
        [
            {"SearchKey": "invoice", "Term": "invoice", "Category": "Invoice", "SeverityWeight": "1"},
            {"SearchKey": "payment", "Term": "payment", "Category": "Payment", "SeverityWeight": "1"},
            {"SearchKey": "wire", "Term": "wire", "Category": "Payment change", "SeverityWeight": "2"},
            {"SearchKey": "bank account", "Term": "bank account", "Category": "Payment change", "SeverityWeight": "2"},
            {"SearchKey": "remittance", "Term": "remittance", "Category": "Payment", "SeverityWeight": "1"},
            {"SearchKey": "ach", "Term": "ach", "Category": "Payment change", "SeverityWeight": "2"},
        ],
    )


if __name__ == "__main__":
    main()
