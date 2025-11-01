# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840530");
  script_cve_id("CVE-2010-1624", "CVE-2010-3711");
  script_tag(name:"creation_date", value:"2010-11-16 13:49:48 +0000 (Tue, 16 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1014-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1014-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the USN-1014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pierre Nogues discovered that Pidgin incorrectly handled malformed SLP
messages in the MSN protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a denial
of service. This issue only affected Ubuntu 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2010-1624)

Daniel Atallah discovered that Pidgin incorrectly handled the return code
of the Base64 decoding function. A remote attacker could send a specially
crafted message and cause Pidgin to crash, leading to a denial of service.
(CVE-2010-3711)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
