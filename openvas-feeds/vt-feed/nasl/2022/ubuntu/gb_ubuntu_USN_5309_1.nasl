# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845262");
  script_cve_id("CVE-2022-0135", "CVE-2022-0175");
  script_tag(name:"creation_date", value:"2022-03-01 02:00:36 +0000 (Tue, 01 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5309-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5309-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5309-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virglrenderer' package(s) announced via the USN-5309-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that virglrenderer incorrectly handled memory. An
attacker inside a guest could use this issue to cause virglrenderer to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2022-0135)

It was discovered that virglrenderer incorrectly initialized memory. An
attacker inside a guest could possibly use this issue to obtain sensitive
host information. (CVE-2022-0175)");

  script_tag(name:"affected", value:"'virglrenderer' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
