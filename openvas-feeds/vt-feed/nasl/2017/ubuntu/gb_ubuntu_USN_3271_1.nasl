# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843148");
  script_cve_id("CVE-2015-7995", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1841", "CVE-2016-4738", "CVE-2017-5029");
  script_tag(name:"creation_date", value:"2017-04-29 05:16:29 +0000 (Sat, 29 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:19:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3271-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3271-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt' package(s) announced via the USN-3271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Holger Fuhrmannek discovered an integer overflow in the
xsltAddTextString() function in Libxslt. An attacker could use
this to craft a malicious document that, when opened, could cause a
denial of service (application crash) or possible execute arbitrary
code. (CVE-2017-5029)

Nicolas Gregoire discovered that Libxslt mishandled namespace
nodes. An attacker could use this to craft a malicious document that,
when opened, could cause a denial of service (application crash)
or possibly execute arbitrary code. This issue only affected Ubuntu
16.04 LTS, Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1683)

Sebastian Apelt discovered that a use-after-error existed in the
xsltDocumentFunctionLoadDocument() function in Libxslt. An attacker
could use this to craft a malicious document that, when opened,
could cause a denial of service (application crash) or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS,
Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1841)

It was discovered that a type confusion error existed in the
xsltStylePreCompute() function in Libxslt. An attacker could use this
to craft a malicious XML file that, when opened, caused a denial of
service (application crash). This issue only affected Ubuntu 14.04
LTS and Ubuntu 12.04 LTS. (CVE-2015-7995)

Nicolas Gregoire discovered the Libxslt mishandled the 'i' and 'a'
format tokens for xsl:number data. An attacker could use this to
craft a malicious document that, when opened, could cause a denial of
service (application crash). This issue only affected Ubuntu 16.04 LTS,
Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1684)

It was discovered that the xsltFormatNumberConversion() function
in Libxslt did not properly handle empty decimal separators. An
attacker could use this to craft a malicious document that, when
opened, could cause a denial of service (application crash). This
issue only affected Ubuntu 16.10, Ubuntu 16.04 LTS, Ubuntu 14.04 LTS,
and Ubuntu 12.04 LTS. (CVE-2016-4738)");

  script_tag(name:"affected", value:"'libxslt' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
