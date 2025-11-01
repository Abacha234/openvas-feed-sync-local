# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845398");
  script_cve_id("CVE-2022-24882", "CVE-2022-24883");
  script_tag(name:"creation_date", value:"2022-06-07 01:00:36 +0000 (Tue, 07 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 13:51:00 +0000 (Fri, 06 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5461-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5461-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5461-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the USN-5461-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP incorrectly handled empty password values. A
remote attacker could use this issue to bypass server authentication. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.10.
(CVE-2022-24882)

It was discovered that FreeRDP incorrectly handled server configurations
with an invalid SAM file path. A remote attacker could use this issue to
bypass server authentication. (CVE-2022-24883)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
