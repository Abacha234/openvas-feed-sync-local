# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840349");
  script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-646-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-646-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-646-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rdesktop' package(s) announced via the USN-646-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that rdesktop did not properly validate the length
of packet headers when processing RDP requests. If a user were tricked
into connecting to a malicious server, an attacker could cause a
denial of service or possible execute arbitrary code with the
privileges of the user. (CVE-2008-1801)

Multiple buffer overflows were discovered in rdesktop when processing
RDP redirect requests. If a user were tricked into connecting to a
malicious server, an attacker could cause a denial of service or
possible execute arbitrary code with the privileges of the user.
(CVE-2008-1802)

It was discovered that rdesktop performed a signed integer comparison
when reallocating dynamic buffers which could result in a heap-based
overflow. If a user were tricked into connecting to a malicious
server, an attacker could cause a denial of service or possible
execute arbitrary code with the privileges of the user.
(CVE-2008-1802)");

  script_tag(name:"affected", value:"'rdesktop' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
