# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843168");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-10217", "CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291");
  script_tag(name:"creation_date", value:"2017-05-17 04:53:09 +0000 (Wed, 17 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3272-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3272-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3272-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1687614");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-3272-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3272-1 fixed vulnerabilities in Ghostscript. This change introduced
a regression when the DELAYBIND feature is used with the eqproc
command. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Ghostscript improperly handled parameters to
 the rsdparams and eqproc commands. An attacker could use these to
 craft a malicious document that could disable -dSAFER protections,
 thereby allowing the execution of arbitrary code, or cause a denial
 of service (application crash). (CVE-2017-8291)

 Kamil Frankowicz discovered a use-after-free vulnerability in the
 color management module of Ghostscript. An attacker could use this
 to cause a denial of service (application crash). (CVE-2016-10217)

 Kamil Frankowicz discovered a divide-by-zero error in the scan
 conversion code in Ghostscript. An attacker could use this to cause
 a denial of service (application crash). (CVE-2016-10219)

 Kamil Frankowicz discovered multiple NULL pointer dereference errors in
 Ghostscript. An attacker could use these to cause a denial of service
 (application crash). (CVE-2016-10220, CVE-2017-5951, CVE-2017-7207)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
