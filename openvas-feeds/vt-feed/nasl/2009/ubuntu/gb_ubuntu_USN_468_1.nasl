# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840113");
  script_cve_id("CVE-2007-1362", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-468-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-468-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-468-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws were discovered in the layout and JavaScript engines.
By tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user's privileges. (CVE-2007-2867,
CVE-2007-2868)

A flaw was discovered in the form autocomplete feature. By tricking
a user into opening a malicious web page, an attacker could cause a
persistent denial of service. (CVE-2007-2869)

Nicolas Derouet discovered flaws in cookie handling. By tricking a user
into opening a malicious web page, an attacker could force the browser to
consume large quantities of disk or memory while processing long cookie
paths. (CVE-2007-1362)

A flaw was discovered in the same-origin policy handling of the
addEventListener JavaScript method. A malicious web site could exploit
this to modify the contents, or steal confidential data (such as
passwords), of other web pages. (CVE-2007-2870)

Chris Thomas discovered a flaw in XUL popups. A malicious web site
could exploit this to spoof or obscure portions of the browser UI,
such as the location bar. (CVE-2007-2871)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
