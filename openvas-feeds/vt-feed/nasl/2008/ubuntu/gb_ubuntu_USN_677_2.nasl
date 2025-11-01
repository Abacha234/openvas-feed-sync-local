# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63074");
  script_cve_id("CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-677-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-677-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-677-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/310359");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org-l10n' package(s) announced via the USN-677-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-677-1 fixed vulnerabilities in OpenOffice.org. The changes required that
openoffice.org-l10n also be updated for the new version in Ubuntu 8.04 LTS.

Original advisory details:

 Multiple memory overflow flaws were discovered in OpenOffice.org's handling of
 WMF and EMF files. If a user were tricked into opening a specially crafted
 document, a remote attacker might be able to execute arbitrary code with user
 privileges. (CVE-2008-2237, CVE-2008-2238)

 Dmitry E. Oboukhov discovered that senddoc, as included in OpenOffice.org,
 created temporary files in an insecure way. Local users could exploit a race
 condition to create or overwrite files with the privileges of the user invoking
 the program. This issue only affected Ubuntu 8.04 LTS. (CVE-2008-4937)");

  script_tag(name:"affected", value:"'openoffice.org-l10n' package(s) on Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
