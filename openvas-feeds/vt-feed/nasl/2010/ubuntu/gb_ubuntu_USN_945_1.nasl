# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840437");
  script_cve_id("CVE-2010-1639", "CVE-2010-2077");
  script_tag(name:"creation_date", value:"2010-05-28 08:00:59 +0000 (Fri, 28 May 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-945-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-945-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the USN-945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ClamAV did not properly reallocate memory when
processing certain PDF files. A remote attacker could send a specially
crafted PDF and crash ClamAV. (CVE-2010-1639)

An out of bounds memory access flaw was discovered in ClamAV. A remote
attacker could send a specially crafted Portable Executable (PE) file
and crash ClamAV. This issue only affected Ubuntu 10.04 LTS.
(CVE-2010-2077)");

  script_tag(name:"affected", value:"'clamav' package(s) on Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
