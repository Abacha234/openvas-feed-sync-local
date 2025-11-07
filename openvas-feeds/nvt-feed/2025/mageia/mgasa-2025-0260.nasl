# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0260");
  script_cve_id("CVE-2025-11173", "CVE-2025-11261", "CVE-2025-32072", "CVE-2025-32696", "CVE-2025-32697", "CVE-2025-32698", "CVE-2025-32699", "CVE-2025-32700", "CVE-2025-3469", "CVE-2025-61635", "CVE-2025-61638", "CVE-2025-61639", "CVE-2025-61640", "CVE-2025-61641", "CVE-2025-61643", "CVE-2025-61646", "CVE-2025-61653");
  script_tag(name:"creation_date", value:"2025-11-06 04:12:34 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-06T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-11-06 05:40:15 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0260)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0260");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0260.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34211");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2025/10/msg00034.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00063.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00121.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/CIXFJVC57OFRBCCEIDRLZCLFGMYGEYTT/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2025-0260 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"i18n XSS vulnerability in HTMLMultiSelectField when sections are used.
(CVE-2025-3469)
'reupload-own' restriction can be bypassed by reverting file.
(CVE-2025-32696)
Cascading protection is not preventing file reversions. (CVE-2025-32697)
LogPager.php: Restriction enforcer functions do not correctly enforce
suppression restrictions. (CVE-2025-32698)
Potential javascript injection attack enabled by Unicode normalization
in Action API. (CVE-2025-32699)
AbuseFilter log interfaces expose global private and hidden filters when
central DB is not available. (CVE-2025-32700)
HTML injection in feed output from i18n message. (CVE-2025-32072)
OATHAuth extension: Reauthentication for enabling 2FA can be bypassed by
submitting a form in Special:OATHManage. (CVE-2025-11173)
Stored i18n Cross-site scripting (XSS) vulnerability in
mw.language.listToText. (CVE-2025-11261)
ConfirmEdit extension: Missing rate limiting in ApiFancyCaptchaReload.
(CVE-2025-61635)
Parsoid: Validation bypass for `data-` attributes. (CVE-2025-61638)
Log entries which are hidden from the creation of the entry may be
disclosed to the public recent change entry. (CVE-2025-61639)
Stored i18n Cross-site scripting (XSS) vulnerability in
Special:RecentChangesLinked. (CVE-2025-61640)
DDoS vulnerability in QueryAllPages API in miser mode. The `maxsize`
value is now ignored in that mode. (CVE-2025-61641)
Suppressed recent changes may be disclosed to the public RCFeeds.
(CVE-2025-61643)
Public Watchlist/RecentChanges pages may disclose hidden usernames when
an individual editor makes consecutive revisions on a single page, and
only some are marked as hidden username. (CVE-2025-61646)
TextExtracts extension: Information disclosure vulnerability in the
extracts API action endpoint due to missing read permission check.
(CVE-2025-61653)
VisualEditor extension: Stored i18n Cross-site scripting (XSS)
vulnerability in `lastModifiedAt` system messages. (CVE-2025-61655)
VisualEditor extension: Missing attribute validation for attributes
unwrapped from `data-ve-attributes`. (CVE-2025-61656)");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.35.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.35.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.35.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.35.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
