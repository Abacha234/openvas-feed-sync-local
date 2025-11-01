# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840062");
  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-546-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-546-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-546-2");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=405584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-546-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-546-1 fixed vulnerabilities in Firefox. The upstream update included
a faulty patch which caused the drawImage method of the canvas element to
fail. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Firefox incorrectly associated redirected sites
 as the origin of 'jar:' contents. A malicious web site could exploit this
 to modify or steal confidential data (such as passwords) from other web
 sites. (CVE-2007-5947)

 Various flaws were discovered in the layout and JavaScript engines. By
 tricking a user into opening a malicious web page, an attacker could
 execute arbitrary code with the user's privileges. (CVE-2007-5959)

 Gregory Fleischer discovered that it was possible to use JavaScript to
 manipulate Firefox's Referer header. A malicious web site could exploit
 this to conduct cross-site request forgeries against sites that relied
 only on Referer headers for protection from such attacks. (CVE-2007-5960)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
