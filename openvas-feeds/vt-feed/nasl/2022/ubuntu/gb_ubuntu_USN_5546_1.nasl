# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845464");
  script_cve_id("CVE-2022-21426", "CVE-2022-21434", "CVE-2022-21443", "CVE-2022-21449", "CVE-2022-21476", "CVE-2022-21496", "CVE-2022-21540", "CVE-2022-21541", "CVE-2022-21549", "CVE-2022-34169");
  script_tag(name:"creation_date", value:"2022-08-05 01:00:32 +0000 (Fri, 05 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 14:26:00 +0000 (Thu, 28 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5546-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5546-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5546-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8, openjdk-17, openjdk-18, openjdk-lts' package(s) announced via the USN-5546-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Neil Madden discovered that OpenJDK did not properly verify ECDSA
signatures. A remote attacker could possibly use this issue to insert,
edit or obtain sensitive information. This issue only affected OpenJDK
17 and OpenJDK 18. (CVE-2022-21449)

It was discovered that OpenJDK incorrectly limited memory when compiling a
specially crafted XPath expression. An attacker could possibly use this
issue to cause a denial of service. This issue was fixed in OpenJDK 8 and
OpenJDK 18. USN-5388-1 and USN-5388-2 addressed this issue in OpenJDK 11
and OpenJDK 17. (CVE-2022-21426)

It was discovered that OpenJDK incorrectly handled converting certain
object arguments into their textual representations. An attacker could
possibly use this issue to cause a denial of service. This issue was
fixed in OpenJDK 8 and OpenJDK 18. USN-5388-1 and USN-5388-2 addressed
this issue in OpenJDK 11 and OpenJDK 17. (CVE-2022-21434)

It was discovered that OpenJDK incorrectly validated the encoded length of
certain object identifiers. An attacker could possibly use this issue to
cause a denial of service. This issue was fixed in OpenJDK 8 and OpenJDK 18.
USN-5388-1 and USN-5388-2 addressed this issue in OpenJDK 11 and OpenJDK 17.
(CVE-2022-21443)

It was discovered that OpenJDK incorrectly validated certain paths. An
attacker could possibly use this issue to bypass the secure validation
feature and expose sensitive information in XML files. This issue was
fixed in OpenJDK 8 and OpenJDK 18. USN-5388-1 and USN-5388-2 addressed this
issue in OpenJDK 11 and OpenJDK 17. (CVE-2022-21476)

It was discovered that OpenJDK incorrectly parsed certain URI strings. An
attacker could possibly use this issue to make applications accept
invalid of malformed URI strings. This issue was fixed in OpenJDK 8 and
OpenJDK 18. USN-5388-1 and USN-5388-2 addressed this issue in OpenJDK 11
and OpenJDK 17. (CVE-2022-21496)

It was discovered that OpenJDK incorrectly generated class code in the
Hotspot component. An attacker could possibly use this issue to obtain
sensitive information. (CVE-2022-21540)

It was discovered that OpenJDK incorrectly restricted access to the
invokeBasic() method in the Hotspot component. An attacker could possibly
use this issue to insert, edit or obtain sensitive information.
(CVE-2022-21541)

It was discovered that OpenJDK incorrectly computed exponentials. An
attacker could possibly use this issue to insert, edit or obtain sensitive
information. This issue only affected OpenJDK 17.
(CVE-2022-21549)

It was discovered that OpenJDK includes a copy of Xalan that incorrectly
handled integer truncation. An attacker could possibly use this issue to
execute arbitrary code. (CVE-2022-34169)");

  script_tag(name:"affected", value:"'openjdk-8, openjdk-17, openjdk-18, openjdk-lts' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
