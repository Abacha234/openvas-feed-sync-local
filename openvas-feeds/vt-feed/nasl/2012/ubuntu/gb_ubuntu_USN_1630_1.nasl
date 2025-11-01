# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841213");
  script_cve_id("CVE-2012-2772", "CVE-2012-2775", "CVE-2012-2776", "CVE-2012-2777", "CVE-2012-2779", "CVE-2012-2784", "CVE-2012-2786", "CVE-2012-2787", "CVE-2012-2788", "CVE-2012-2789", "CVE-2012-2790", "CVE-2012-2793", "CVE-2012-2794", "CVE-2012-2796", "CVE-2012-2798", "CVE-2012-2800", "CVE-2012-2801", "CVE-2012-2802");
  script_tag(name:"creation_date", value:"2012-11-15 06:17:49 +0000 (Thu, 15 Nov 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1630-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1630-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1630-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libav' package(s) announced via the USN-1630-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Libav incorrectly handled certain malformed media
files. If a user were tricked into opening a crafted media file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program.");

  script_tag(name:"affected", value:"'libav' package(s) on Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
